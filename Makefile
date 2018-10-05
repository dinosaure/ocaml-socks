all: lib lib-lwt lib-mirage docs
	echo good

lib:
	ocaml pkg/pkg.ml build

lib-lwt:
	ocaml pkg/pkg-lwt.ml build

lib-mirage:
	ocaml pkg/pkg-mirage.ml build

docs:
	topkg doc

clean:
	ocaml pkg/pkg.ml clean
	ocaml pkg/pkg-lwt.ml clean
	ocaml pkg/pkg-mirage.ml clean
