open Socks
open Lwt
open Cmdliner
open Rresult

type t = {
  oc: Lwt_io.output Lwt_io.channel;
  ic: Lwt_io.input Lwt_io.channel;
}

let of_socket socket =
  let oc = Lwt_io.of_fd ~mode:Lwt_io.output socket in
  let ic = Lwt_io.of_fd ~mode:Lwt_io.input socket in
  {oc; ic}

let connect ~proxy ~host ~port =
  let connect_str = R.get_ok (Socks.make_socks5_request (Connect {address = Domain_address host; port = port})) in
  let socket = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
  let%lwt host_info = Lwt_unix.gethostbyname proxy in
  let server_address = host_info.Lwt_unix.h_addr_list.(0) in
  let%lwt () = Lwt_unix.connect socket (Lwt_unix.ADDR_INET (server_address, 1080)) in
  Logs.info (fun m -> m "Connected to proxy %s" proxy);
  return socket

let send_connect_request socket host port =
  let connect_str = R.get_ok (Socks.make_socks5_request (Connect {address = Domain_address host; port = port})) in
  Lwt_unix.write_string socket connect_str 0 (String.length connect_str)

let connect proxy host port =
  let%lwt socket = connect_to_proxy proxy in
  let auth_request = make_socks5_auth_request ~username_password:false in
  let auth_response = Bytes.make 2 '\x00' in
  let connect_response = Bytes.make 10 '\x00' in
  let%lwt _ = Lwt_unix.write_string socket auth_request 0 (String.length auth_request) in
  let%lwt _ = Lwt_unix.read socket auth_response 0 2 in
  let auth_method = parse_socks5_auth_response (Bytes.to_string auth_response) in
  begin match auth_method with
    | No_acceptable_methods -> Logs.err (fun m -> m "No acceptable auth methods")
    | _ -> Logs.info (fun m -> m "Auth OK")
  end;
  let%lwt _ = send_connect_request socket host port in
  let%lwt _ = Lwt_unix.read socket connect_response 0 10 in
  let c = parse_socks5_response (Bytes.to_string connect_response) in
  begin match c with
    | Ok _ -> Logs.info (fun m -> m "Connect request ok")
    | Error _ -> Logs.err (fun m -> m "Connect failed")
  end;
  return socket

let http_head socket =
  let conn = of_socket socket in
  let%lwt () = Lwt_io.write conn.oc "HEAD / HTTP/1.0\r\n\r\n" in
  let%lwt head = Lwt_io.read conn.ic in
  Logs.info (fun m -> m "Head: %s" head);
  return ()

let client _ proxy host port =
  Lwt_main.run (let%lwt socket = connect proxy host port in http_head socket)

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ());
  ()

let logging =
  let env = Arg.env_var "SOCKS_CLIENT_VERBOSITY" in
  Term.(const setup_log $ Fmt_cli.style_renderer () $ Logs_cli.level ~env ())
let proxy =
  let doc = "Proxy" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"PROXY" ~doc)
let host =
  let doc = "Host" in
  Arg.(required & pos 1 (some string) None & info [] ~docv:"HOST" ~doc)
let port =
  let doc = "Port" in
  Arg.(required & pos 2 (some int) None & info [] ~docv:"PORT" ~doc)

let cmd =
  let doc = "SOCKS5 client" in
  let exits = Term.default_exits in
  Term.(const client $ logging $ proxy $ host $ port),
  Term.info "socks_client" ~doc ~exits

let () = Term.(eval cmd |> exit)
