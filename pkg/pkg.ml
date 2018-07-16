#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =

  let opams =
    [ Pkg.opam_file "socks.opam"
    ] in

  Pkg.describe ~opams "socks" @@ fun c ->
  begin match Conf.pkg_name c with
    | "socks" ->
      Ok
        [ Pkg.mllib ~api:["Socks"] "src/socks.mllib"
        ; Pkg.test "test/test"
          ;
        ]
    | "socks-lwt" ->
      Error (`Msg "You need to build socks-lwt with \
                   topkg bu --pkg-file pkg/pkg-lwt.ml")
    | _ -> Error (`Msg "pkg.ml called with invalid pkg name")
  end
