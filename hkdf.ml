
module type S = sig
  val extract : ?salt:string -> string -> string
  val expand : prk:string -> ?info:string -> int -> string
end

module Make (H : Digestif.S) : S = struct
  let extract ?salt ikm =
    let key = match salt with
      | None -> String.make H.digest_size '\x00'
      | Some x -> x
    in
    H.(to_raw_string (hmac_string ~key ikm))

  let expand ~prk ?info len =
    let info = match info with
      | None -> ""
      | Some x -> x
    in
    let t n last =
      let nc = String.make 1 (Char.unsafe_chr n) in
      H.(to_raw_string (hmac_string ~key:prk (String.concat "" [last ; info ; nc])))
    in
    let n = succ (len / H.digest_size) in
    let rec compute acc count = match count, acc with
      | c, xs when c > n -> String.concat "" (List.rev xs)
      | c, x::_ -> compute (t c x :: acc) (succ c)
      | _, [] -> invalid_arg "can not happen"
    in
    let buf = compute [""] 1 in
    String.sub buf 0 len
end

let extract ~hash ?salt ikm =
  let module H = (val (Digestif.module_of_hash' hash)) in
  let module HKDF = Make (H) in
  HKDF.extract ?salt ikm

let expand ~hash ~prk ?info len =
  let module H = (val (Digestif.module_of_hash' hash)) in
  let module HKDF = Make (H) in
  HKDF.expand ~prk ?info len
