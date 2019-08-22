open QCheck
open QCheck.Test
open OUnit2
open Socks

let bigendian_port_of_int port =
  String.concat ""
    [
      (port land 0xff00) lsr 8 |> char_of_int |> String.make 1
    ;  port land 0xff          |> char_of_int |> String.make 1
    ]

let asciiz =
  (* generate strings without nullbytes *)
  let ig = QCheck.Gen.int_range 1 0xff in
  let cg = QCheck.Gen.map (char_of_int) ig in
  QCheck.Gen.string ~gen:cg |> QCheck.make

let test_making_a_request _ =
  check_exn @@ QCheck.Test.make ~count:10000
    ~name:"making a request is a thing"
    (triple string string small_int)
    @@ (fun (username, hostname, port) ->
      begin match make_socks4_request ~username ~hostname port with
      | Ok data ->
           data = ("\x04\x01"
                ^ bigendian_port_of_int port
                ^ "\x00\x00\x00\xff"
                ^ username ^ "\x00"
                ^ hostname ^ "\x00")
      | Error (`Msg "Invalid_hostname") when 0 = String.length hostname
                                 || 255 < String.length hostname -> true
      | _ -> false
      end
      );
;;

let test_parsing_a_request _ =
  check_exn @@ QCheck.Test.make ~count:10000
    ~name:"parsing a request is a thing"
    (quad asciiz asciiz small_int string)
    @@ (fun (q_username, q_hostname, q_port, extraneous) ->
      let data = ("\x04\x01"
                ^ bigendian_port_of_int q_port
                ^ "\x00\x00\x00\xff"
                ^ q_username ^ "\x00"
                ^ q_hostname ^ "\x00"
                ^ extraneous)
      in
      begin match parse_request data with
      | Ok Socks4_request (out, x) when x = extraneous
          && out = { port = q_port
                   ; address = q_hostname
                   ; username = q_username} -> true
      | Ok Socks4_request (_, _) -> false
      | Error `Invalid_request when 0 = String.length q_hostname
                          || 255 < String.length q_hostname -> true
      | Error `Invalid_request
      | Error `Incomplete_request
      | Ok Socks5_method_selection_request (_, _) -> false
      end
      );
;;

let test_integrity _ =
  begin
    match Socks.(parse_socks4_response (make_socks4_response ~success:true))
    with
    | Error _ -> failwith "integrity: couldn't make valid OK response"
    | Ok "" -> ()
    | Ok _ -> failwith "integrity: why do we think there is extraneous data?"
  end ;
    begin
    match Socks.(parse_socks4_response (make_socks4_response ~success:false))
    with
    | Error Rejected -> ()
    | _ -> failwith "integrity: couldn't make valid FAIL response"
  end

let suite = [
  "make_socks4_request" >:: test_making_a_request;
  "parse_socks4_request">:: test_parsing_a_request;
  "socks4 self-integrity" >:: test_integrity;
  ]
