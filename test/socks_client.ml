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
  Logs.info (fun m -> m "Connected via %s to %s, port %d" proxy host port);
  let conn = of_socket socket in
  let%lwt () = Lwt_io.write conn.oc "\005\001\000" in
  let%lwt response = Lwt_io.read ~count:2 conn.ic in
  Logs.info (fun m -> m "Connection result: %d bytes" (String.length response));
  return conn

let client _ proxy host port =
  Lwt_main.run (connect ~proxy ~host ~port)

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
