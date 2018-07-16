#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =

  let opams =
    [ Pkg.opam_file "socks-lwt.opam"
    ] in

  Pkg.describe ~metas:[Pkg.meta_file "lwt/META"]
    ~opams "socks-lwt" @@ fun c ->
  begin match Conf.pkg_name c with
    | "socks-lwt" ->
      Ok [
        Pkg.mllib ~api:["Socks_lwt"] "src/socks_lwt.mllib"
      ]
    | _ -> Error (`Msg "pkg.ml called with invalid pkg name")
  end
