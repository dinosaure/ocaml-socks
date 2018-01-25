open Socks
open Socks_types
open Lwt
open Cmdliner

let connect ~proxy ~host ~port =
  let socket = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
  let%lwt host_info = Lwt_unix.gethostbyname proxy in
  let server_address = host_info.Lwt_unix.h_addr_list.(0) in
  let%lwt () = Lwt_unix.connect socket (Lwt_unix.ADDR_INET (server_address, 1080)) in
  Logs.info (fun m -> m "Connected via %s to %s, port %d" proxy host port);
  return (socket)

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
