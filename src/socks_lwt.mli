(** Lwt helper module for dealing with SOCKS servers and clients using the
    [Lwt] lightweight threading library.*)

(** {1 Types}*)

open Rresult
open Socks_types

type channel =
  Lwt_io.input_channel * Lwt_io.output_channel
(** A bi-directional communication channel *)

type client_data_cb = string -> channel -> unit Lwt.t
(** takes the extraneous input returned from the last parsing function,
    the client channel, and returns a thread that handles the I/O between
    client and target after the connection has been established.
*)

type 'error request_policy =
  [ `Socks4 of socks4_request
  | `Socks5 of socks5_request ] ->
  (client_data_cb, 'error) Lwt_result.t
  constraint 'error = [> Rresult.R.msg ]
(** A request policy is a function that takes a [request] and returns
    a callback for performing the I/O of the allowed connection, or
    an ['error] if the [request] is not permitted.
    The request policy is responsible for making the connection to the
    requested address.
    The I/O callback could for instance be the {!forward_data} helper if you do
    not wish to modify the data.
*)

type ('req_err, 'auth_err) auth_callback =
  socks5_authentication_method ->
  (([> R.msg] as 'req_err) request_policy, 'auth_err) Lwt_result.t
(** An [auth_callback auth_method] is the {!request_policy}
    for the server to use for validating requests if the authentication
    succeeded, and an error if the authentication is rejected.
    This is the function that would receive the username/password of the client
    when using that authentication method, for instance.
*)

type ('req_err, 'auth_err) auth_policy =
  socks5_method_selection_request ->
  ( socks5_authentication_method * ('req_err, R.msg as 'auth_err) auth_callback,
    'auth_err) Lwt_result.t
(** Authentication policies are Lwt threads that select a desired authentication
    method for use by the client, and return a {!auth_callback} used to validate
    the client's credentials once they have been received by the server.
    If the client's {i method selection request} does not contain an
    appropriate authentication method, the authentication policy should reject
    the client by returning an error.
*)

type ('req_err, 'auth_error, 'addr_err) address_policy =
  Lwt_unix.sockaddr -> (([> R.msg] as 'req_err, 'auth_error) auth_policy,
                        ([> R.msg] as 'addr_err)) Lwt_result.t
(** Address policies filter connecting clients based on their IP and
    source port number.*)


(** {1:client Making a client connection} *)


(** TODO write this section.

    Maybe you can glean some tips from
    {{:https://github.com/ekoeppen/ocaml-socks5-client} Eckhart Köppen's fork}
*)


(** {1:server Running a SOCKS server} *)


val easy_establish_server : unit -> Lwt_io.server Lwt.t
(** [easy_establish_server ()] is a local proxy server that listens on
    [127.0.0.1:1080], and allows all clients.
    It handles both SOCKS4{_ A}  and SOCKS5 requests to any destination.
    It is an alias of:[
    ]{!establish_server}[ 127.0.0.1:1080
      (]{!client_allow_localhost}[
        ]{!resolve_dns_and_forward_tcp}[)]
*)

val easy_establish_pw_server : username:string -> password:string ->
  Lwt_io.server Lwt.t
(** [easy_establish_pw_server username password] is {!easy_establish_server}
    with {!auth_username_password}[ (fun (u,p) -> u = username && p = password)]
    instead of {!auth_allow_all}.

    That is, it only accepts clients providing the correct
    [username] and [password] combination.
*)

val establish_server :
  Lwt_unix.sockaddr -> (R.msg,R.msg,R.msg) address_policy ->
  Lwt_io.server Lwt.t
(** [establish_server listen_addr client_policy request_policy] is a server
    that listens on [listen_addr], using [client_policy] to perform access
    control based on the addresses of connecting clients, and
    [request_policy] to validate the requested connection targets.*)

(** {1:helpers General helper functions} *)

val forward_data : channel -> string -> channel -> unit Lwt.t
(** [forward_data upstream leftover client] forwards bytes
    in both directions between [client] and [upstream],
    ending when either side of the connection hangs up
    (after flushing the buffered channels).
    At the beginning, [leftover] is sent to [upstream] {b before} any data
    received via the [client] channel.
*)


(** {1:policies Helper functions for constructing policies} *)


(** {2:policies_requests Request policies} *)

val resolve_dns_and_forward_tcp : [> R.msg] request_policy
(** [resolve_dns_and_forward_tcp client_channel] is a {!request_policy}
    that permits any address and tries to establishes a TCP connection
    (over either IPv4 or IPv6) to the target,
    transferring the data between client and server using {!forward_data}.
*)

(** {2:policies_auth Authentication policies} *)

val auth_allow_all :
  ([> R.msg] as 'req_err) request_policy ->
  ('req_err, 'auth_err) auth_policy

val auth_username_password : (socks5_username * socks5_password -> bool) ->
  ('req_err) request_policy ->
  ('req_err, [> R.msg]) auth_policy
(** [auth_username_password auth_cb] is an authentication policy that mandates
    RFC 1929 Username/Password authentication and uses [auth_cb] to validate the
    username/password combination received from the client.

    Note that for SOCKS4{_ A} clients the username is offered as a potential
    authenticator (with an empty password string, since SOCKS 4{_ A} does not
    support password authentication).
*)

(** {2:policies_client Client policies} *)

val client_allow_all :
  (('req_err,'auth_err) auth_policy) ->
  ('req_err, 'auth_err, 'client_err) address_policy
(** [client_allow_all request_policy] is an address policy that permits
    any client address to connect, and returns [request_policy] for validating
    their SOCKS request.*)

val client_allow_localhost :
    (('req_err,'auth_err) auth_policy) ->
  ('req_err, 'auth_err, 'client_err) address_policy
(** [client_allow_localhost] is an address policy that permits
    clients connecting from [localhost], and returns [request_policy]
    for validating their SOCKS request.*)


(** {1:examples Examples} *)


(** {2:writing_an_address_policy Writing an address policy} *)
(** This is the implementation for {!client_allow_localhost}:
    [let client_allow_localhost auth_policy : ('a,'b, R.msg) address_policy =
    function
    | Unix.ADDR_INET (addr,_) when addr = Unix.inet_addr_loopback
                              ||   addr = Unix.inet6_addr_loopback ->
        Lwt_result.return (auth_policy)
    | _ ->
        Lwt_result.fail (`Msg "Client addr not allowed.")
    ]
*)

(** {2:writing_an_auth_policy Writing an authentication policy} *)
(** See {!auth_policy} for a brief explanation of authentication policies.

    The implementation for {!auth_username_password} looks roughly like this:

    [let auth_username_password auth_cb request_policy : _ auth_policy =
    fun method_selection_request ->
    if List.exists (function
                    | Username_password _ -> true
                    | _ -> false)
       method_selection_request
    then begin
      Lwt_result.return (
        Username_password ("","") (* tell the client to provide user/pw *)
        ,
        function
        | Username_password user_pw ->
          (* we now have the credentials in [user_pw]: *)
          if auth_cb user_pw then
            (* user gave correct user/pw: *)
            Lwt_result.return request_policy
          else
            Lwt_result.fail (`Msg "Incorrect user/pw from client.")
        | _ ->
          Lwt_result.fail (`Msg "Client did not respond with user/pw \
                                 authentication when prompted for such.")
      )
    end else
      Lwt_result.fail (`Msg "Client did not offer user/pw auth")
    ]
*)

(** {2:testing_your_server Testing connections to your server} *)
(** I found it useful to test making various connections to the server,
    here are some command examples:

    - Starting a test "upstream" / target: [
    nc -vlp 9000]
    - SOCKS 4{_ A}: Domain-name ATYP:[
    socat -v - socks4a:127.0.0.1:localhost:9000]
    - SOCKS 4{_ A}: Domain-name ATYP with username "hello":[
    socat -v - socks4a:127.0.0.1:localhost:9000,socksuser=hello]
    - SOCKS 4{_ A}: Domain-name ATYP containing IP address:[
    socat -v - socks4a:127.0.0.1:127.1.2.3:9000]
    - SOCKS 5: IPv4 ATYP with username "hello":[
    ncat --proxy-type socks5 --proxy 127.0.0.1:1080 --proxy-auth 'hello:' 127.0.0.2 9000]
    - SOCKS 5: IPv6 ATYP address [::] port 9000:[
    ncat --proxy-type socks5 --proxy 127.0.0.1:1080 --proxy-auth 'hello:' :: 9000]
*)
