(* SOCKS helper. Wraps a Lwt file_descr *)

open Rresult
open Lwt
open Socks

type channel = Lwt_io.input_channel * Lwt_io.output_channel
type client_data_cb = string -> channel -> unit Lwt.t
(* leftover_bytes from client -> client channel -> Lwt.t *)

type 'error request_policy =
     [ `Socks4 of Socks.socks4_request | `Socks5 of Socks.socks5_request ]
  -> (client_data_cb, 'error) Lwt_result.t
  constraint 'error = [> Rresult.R.msg ]

type ('req_err, 'auth_err) auth_callback =
     Socks.socks5_authentication_method
  -> (([> R.msg ] as 'req_err) request_policy, 'auth_err) Lwt_result.t

type ('req_err, 'auth_err) auth_policy =
     Socks.socks5_method_selection_request
  -> ( Socks.socks5_authentication_method
       * ('req_err, (R.msg as 'auth_err)) auth_callback
     , 'auth_err )
     Lwt_result.t

type ('req_error, 'auth_error, 'addr_error) address_policy =
     Lwt_unix.sockaddr
  -> ( (([> R.msg ] as 'req_error), ([> R.msg ] as 'auth_error)) auth_policy
     , ([> R.msg ] as 'addr_error) )
     Lwt_result.t

module Socks_log : Logs.LOG = (val Logs.(src_log @@ Src.create "socks.lwt"))

let auth_allow_all (request_policy : 'req_err request_policy) :
    ('req_err, [> R.msg ]) auth_policy =
 fun _method_selection_request ->
  Lwt_result.return
    ( No_authentication_required
    , function
      | No_authentication_required | Username_password _ ->
          Lwt.return (Ok request_policy)
      | _ ->
          Lwt_result.fail
            (`Msg
              "invalid auth type passed for request for \
               No_authentication_required") )

let auth_username_password auth_cb (request_policy : 'req_err request_policy) :
    ('req_err, [> R.msg ]) auth_policy =
 fun method_selection_request ->
  if
    List.exists
      (function Username_password _ -> true | _ -> false)
      method_selection_request
  then (
    Socks_log.app (fun m -> m "was offered username auth");
    Lwt_result.return
      ( Username_password ("", "")
      , function
        | Username_password user_pw ->
            Socks_log.app (fun m -> m "got user/pw from client");
            if auth_cb user_pw then (
              Socks_log.info (fun m -> m "user gave correct user/pw");
              Lwt_result.return request_policy)
            else Lwt_result.fail (`Msg "Incorrect user/pw from client.")
        | _ ->
            Lwt_result.fail
              (`Msg
                "Client did not respond with user/pw authentication when \
                 prompted for such.") ))
  else Lwt_result.fail (`Msg "Client did not offer user/pw auth")

let read_while_incomplete (type ok) channel
    (f : string -> (ok, [< `Incomplete_request | `Invalid_request ]) Result.t)
    (acc : string) : (ok, [< `Invalid_request ]) Lwt_result.t =
  let rec loop acc =
    Lwt_io.read ~count:128 (fst channel) >>= fun str ->
    if str = "" then (
      Logs.err (fun m -> m "EOF from client");
      Lwt.return (Error `Invalid_request))
    else
      let joined = acc ^ str in
      match f joined with
      | Error `Incomplete_request -> loop joined
      | Error `Invalid_request as res ->
          Logs.debug (fun m -> m "Invalid request: %S" joined);
          Lwt.return res
      | Ok _ as res -> Lwt.return res
  in
  loop acc

let connect_with address port : (channel, [> R.msg ]) Lwt_result.t =
  let ai_families, address =
    let open Lwt_unix in
    match address with
    | IPv4_address addr -> ([ PF_INET ], Ipaddr.V4.to_string addr)
    | IPv6_address addr -> ([ PF_INET6 ], Ipaddr.V6.to_string addr)
    | Domain_address addr -> ([ PF_INET; PF_INET6 ], addr)
  in
  let open Lwt_unix in
  Lwt_list.fold_left_s
    (function
      | Some _ as acc -> fun _ -> Lwt.return acc
      | None ->
          fun req_ai_family ->
            Lwt.catch
              (fun () ->
                getaddrinfo address (string_of_int port)
                  [ AI_SOCKTYPE SOCK_STREAM; AI_FAMILY req_ai_family ]
                >|= function
                | {
                    ai_protocol= 6 (*TCP*)
                  ; ai_socktype= SOCK_STREAM
                  ; ai_family
                  ; ai_addr= ADDR_INET (addr, port)
                  ; ai_canonname= _
                  }
                  :: _
                  when ai_family = req_ai_family ->
                    Some (addr, port)
                | _ :: _ ->
                    Socks_log.debug (fun m ->
                        m
                          "connect_with: Resolved sockaddr was not TCP / \
                           SOCK_STREAM / (IPv4|IPv6)");
                    None
                | [] ->
                    Socks_log.debug (fun m ->
                        m
                          "connect_with: failed to get (%s socket) for resolve \
                           %s:%d"
                          (match req_ai_family with
                          | PF_INET -> "IPv4"
                          | PF_INET6 -> "IPv6"
                          | PF_UNIX -> "UNIX")
                          address port);
                    None)
              (fun _ -> Lwt.return None))
    None ai_families
  >>= function
  | Some (addr, port) ->
      Socks_log.debug (fun m -> m "Connecting to %S:%d" address port);
      Lwt.catch
        (fun () ->
          Lwt_result.ok @@ Lwt_io.open_connection (ADDR_INET (addr, port)))
        (fun _ -> Lwt_result.fail (`Msg "unable to connect"))
  | None -> Lwt_result.fail (`Msg "couldn't resolve")

let forward_data (upstream_in, upstream_out) : client_data_cb =
 fun original_leftover ((client_in, client_out) : channel) ->
  let handle_data fd_in fd_out =
    let rec loop () =
      Lwt_io.read ~count:2048 fd_in >>= function
      | "" ->
          Socks_log.err (fun m -> m "SOCKS EOF");
          Lwt_io.flush client_out >>= fun () -> Lwt_io.flush upstream_out
      | msg ->
          Logs.debug (fun m -> m "-> %S" msg);
          Lwt_io.write fd_out msg >>= fun () -> loop ()
    in
    Lwt.catch
      (fun () ->
        Lwt_io.write upstream_out original_leftover >>= fun () -> loop ())
      (function
        | Unix.Unix_error (Unix.ECONNRESET, _, _) | _ -> Lwt.return_unit)
  in
  Socks_log.debug (fun m -> m "entering forward_data loop");
  Lwt.pick
    [ handle_data upstream_in client_out; handle_data client_in upstream_out ]
  >>= fun _ ->
  Lwt_io.close upstream_in >>= fun () -> Lwt_io.close upstream_out

let reply_to_socks4_connect ((_, client_out) : channel) resolved =
  Lwt_io.write client_out
    (match resolved with
    | Ok _ ->
        Socks_log.debug (fun m -> m "socks4: telling the client it went well: ");
        make_socks4_response ~success:true
    | Error _ ->
        Socks_log.debug (fun m ->
            m "socks4: telling the client it DID NOT go well");
        make_socks4_response ~success:false)
  >>= fun () ->
  Lwt_io.flush client_out >|= fun () -> resolved

let reply_to_socks5_connect ((_, client_out) : channel)
    (res : (socks5_struct * unit Lwt.t, 'error) Rresult.result) :
    (socks5_struct * unit Lwt.t, 'error) Lwt_result.t =
  (match res with
  | Ok (resolved, _) ->
      ( (fun fmt _ -> Format.pp_print_string fmt "Succeeded")
      , make_socks5_response Succeeded ~bnd_port:0 resolved.address )
  | Error (`Msg error as msg) ->
      Socks_log.err (fun m -> m "Socks5 CONNECT: %a" R.pp_msg msg);
      ( (fun fmt _ -> Format.pp_print_string fmt ("Error: " ^ error))
      , make_socks5_response General_socks_server_failure ~bnd_port:0
          (IPv4_address (Ipaddr.V4.of_octets_exn "\x00\x00\x00\x00")) ))
  |> function
  | status, Ok response_str ->
      Socks_log.debug (fun m ->
          m "Writing SOCKS5 CONNECT response: %a %S" status () response_str);
      Lwt_io.write client_out response_str >>= fun () ->
      Lwt_io.flush client_out >|= fun () -> res
  | _, Error x ->
      Socks_log.err (fun m ->
          m "Unable to generate SOCKS5 CONNECT reply: %a" R.pp_msg x);
      Lwt.return res

let resolve_dns_and_forward_tcp : 'error request_policy = function
  | `Socks4 req ->
      let open Lwt_result in
      connect_with (Domain_address req.address) req.port >>= fun upstream ->
      Lwt_result.return (forward_data upstream)
  | `Socks5 (Connect { address; port }) -> (
      Socks_log.debug (fun m -> m "ooh fancy it's socks5");
      let open Lwt in
      connect_with address port >>= fun upstream ->
      (* return I/O promise or explain what went wrong: *)
      match upstream with
      | Ok upstream -> Lwt.return (Ok (forward_data upstream))
      | Error _ -> Lwt_result.fail (`Msg "can't connect to target address"))
  | `Socks5 (UDP_associate _) ->
      Lwt_result.fail (`Msg "resolve_dns_and_forward_tcp: UDP")
  | `Socks5 (Bind _) ->
      Lwt_result.fail (`Msg "resolve_dns_and_forward_tcp: Bind")

let client_allow_all (auth_policy : ('a, 'b) auth_policy) :
    ('a, 'b, 'c) address_policy =
 fun (_client_addr : Lwt_unix.sockaddr) ->
  (* Since we allow everything, we just return Ok _:*)
  Lwt_result.return (* Pass to the specified auth_policy next: *) auth_policy

let client_allow_localhost (auth_policy : ('a, 'b) auth_policy) :
    ('a, 'y, 'z) address_policy = function
  | Unix.ADDR_INET (addr, _)
    when addr = Unix.inet_addr_loopback || addr = Unix.inet6_addr_loopback ->
      Lwt_result.return auth_policy
  | _ -> Lwt_result.fail (`Msg "Client addr not allowed.")

let get_socks_connect_or_auth_request (client_chan : channel) old_leftover =
  Lwt_result.bind_lwt_error
    (read_while_incomplete client_chan Socks.parse_request old_leftover)
    (fun `Invalid_request ->
      Lwt.return @@ `Msg "got invalid initial message from client")

let establish_server server_addr
    (address_policy : ([> R.msg ], [> R.msg ], [> R.msg ]) address_policy) =
  Lwt_io.establish_server_with_client_address server_addr
    (fun sockaddr (client_channel : channel) ->
      (address_policy : ([> R.msg ], [> R.msg ], [> R.msg ]) address_policy)
        sockaddr
      >>= function
      | Error (`Msg msg) ->
          Socks_log.err (fun m ->
              m "address policy: client NOT ALLOWED: %s" msg);
          Lwt.return_unit
      | Ok auth_policy -> (
          Socks_log.debug (fun m -> m "got client from allowed address.");
          get_socks_connect_or_auth_request client_channel "" >>= fun req_res ->
          match req_res with
          | Error msg ->
              Socks_log.err (fun m ->
                  m "aborting client connection while reading request: %a"
                    R.pp_msg msg);
              Lwt.return_unit
          | Ok (Socks4_request (socks4_request, req_leftover)) -> (
              auth_policy
                [ No_authentication_required; Username_password ("", "") ]
              >>= (function
                    | Ok
                        ( (( No_authentication_required
                           | Username_password ("", "") ) as selected_auth)
                        , auth_cb ) -> (
                        auth_cb
                          (match selected_auth with
                          | Username_password ("", "") ->
                              Username_password (socks4_request.username, "")
                          | none -> none)
                        >>= function
                        | Ok request_policy -> (
                            request_policy (`Socks4 socks4_request) >|= function
                            | Ok _ as data_cb -> data_cb
                            | Error msg ->
                                Logs.err (fun m ->
                                    m "SOCKS4A request policy: %a" R.pp_msg msg);
                                Error ())
                        | Error auth_msg ->
                            Logs.err (fun m ->
                                m "SOCKS4A auth check: %a" R.pp_msg auth_msg);
                            Lwt_result.fail ())
                    | Ok _ ->
                        Logs.err (fun m ->
                            m "SOCKS4A auth select: socks5 auth method selected");
                        Lwt_result.fail ()
                    | Error msg ->
                        Logs.err (fun m ->
                            m "SOCKS4A auth select: %a" R.pp_msg msg);
                        Lwt_result.fail ())
              >>= reply_to_socks4_connect client_channel
              >>= function
              | Ok data_cb -> data_cb req_leftover client_channel
              | Error () -> Lwt.return_unit)
          | Ok (Socks5_method_selection_request (methods, method_leftover)) -> (
              auth_policy methods
              >>= (function
                    | Error (`Msg msg) ->
                        Lwt_result.fail (`Msg ("auth policy: " ^ msg))
                    | Ok (auth_method, verify_auth) -> (
                        Lwt_io.write (snd client_channel)
                          (make_socks5_auth_response auth_method)
                        >>= fun () ->
                        Lwt_io.flush (snd client_channel) >>= fun () ->
                        (match auth_method with
                        | No_authentication_required ->
                            let open Lwt_result in
                            verify_auth No_authentication_required
                            >|= fun auth_res -> (auth_res, method_leftover)
                        | No_acceptable_methods ->
                            Lwt_result.fail (`Msg "no acceptable auth methods")
                        | Username_password _ -> (
                            read_while_incomplete client_channel
                              parse_socks5_username_password_request
                              method_leftover
                            >>= function
                            | Ok (`Username_password (a, b, leftover)) -> (
                                ( verify_auth (Username_password (a, b))
                                >>= fun res ->
                                  Lwt_io.write (snd client_channel)
                                    (make_socks5_username_password_response
                                       ~accepted:(R.is_ok res))
                                  >|= fun () -> res )
                                >>= function
                                | Ok auth_res ->
                                    Lwt_result.return (auth_res, leftover)
                                | Error _ ->
                                    Lwt_result.fail (`Msg "Invalid user/pw"))
                            | Error `Invalid_request ->
                                Lwt_result.fail
                                  (`Msg "error parsing user/pw request")))
                        >>= function
                        | Error _ as err -> Lwt.return err
                        | Ok (request_policy, auth_leftover) -> (
                            Socks_log.debug (fun m ->
                                m
                                  "SOCKS5: got a client request policy, now \
                                   reading request.");
                            read_while_incomplete client_channel
                              parse_socks5_connect auth_leftover
                            >>= function
                            | Error `Invalid_request ->
                                Lwt_result.fail (`Msg "unable to parse CONNECT")
                            | Ok (request, req_leftover) -> (
                                request_policy (`Socks5 (Connect request))
                                >>= function
                                | Ok client_cb ->
                                    Socks_log.debug (fun m ->
                                        m
                                          "Client request validated, starting \
                                           data callback.");
                                    Lwt_result.return
                                      ( request
                                      , client_cb req_leftover client_channel )
                                | Error (`Msg req_msg) ->
                                    Socks_log.err (fun m ->
                                        m "request policy rejected: %s" req_msg);
                                    Lwt_result.fail (`Msg req_msg)))))
              >>= reply_to_socks5_connect client_channel
              >>= function
              | Ok (_request, data_cb) ->
                  data_cb >>= fun () -> Lwt_io.flush (snd client_channel)
              | Error _ -> Lwt.return_unit)))

let easy_establish_server () =
  Lwt.wrap (fun () ->
      Socks_log.debug (fun m -> m "starting easy_open_server");
      Lwt_unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1080))
  >>= fun server_addr ->
  establish_server server_addr
    (client_allow_localhost (auth_allow_all resolve_dns_and_forward_tcp))

let easy_establish_pw_server ~username ~password =
  Lwt.wrap (fun () ->
      Socks_log.debug (fun m -> m "starting easy_open_pw_server");
      Lwt_unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1080))
  >>= fun server_addr ->
  establish_server server_addr
    (client_allow_localhost
       (auth_username_password
          (fun (u, p) -> u = username && p = password)
          resolve_dns_and_forward_tcp))

let easy_connect_socks4a_client ?(socks_port = 1080) ?(username = "") ~server
    hostname port =
  Lwt.wrap (fun () ->
      Socks_log.debug (fun m -> m "resolving %s:%d" server socks_port);
      Lwt_unix.ADDR_INET (Unix.inet_addr_of_string server, socks_port))
  >>= fun server_addr ->
  make_socks4_request ~username ~hostname port |> R.get_ok |> fun request ->
  Lwt_io.open_connection server_addr
  >>= fun ((server_in, server_out) as socket) ->
  Lwt_io.write_from_string_exactly server_out request 0 (String.length request)
  >>= fun () ->
  Lwt_io.flush server_out >>= fun () ->
  let resp_buf = Bytes.make 1024 '\000' in
  let rec loop offset =
    if offset >= 1024 then Lwt.return (Error (`Msg "Invalid response"))
    else
      Lwt_io.read_into server_in resp_buf offset (Bytes.length resp_buf - offset)
      >>= function
      | 0 -> Lwt.return (Error (`Msg "Connection died"))
      | rcvd -> (
          let offset = offset + rcvd in
          match
            Socks.parse_socks4_response (Bytes.sub_string resp_buf 0 offset)
          with
          | Ok leftover -> Lwt.return (Ok (socket, leftover))
          | Error Rejected -> Lwt.return (Error (`Msg "Rejected"))
          | Error Incomplete_response -> loop offset)
  in
  loop 0
