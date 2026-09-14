<?php
function build_key($bits) {
    return openssl_pkey_new(array("private_key_bits" => $bits));
}

function legacy_key() {
    return build_key(1024);
}

function digest($algo, $data) {
    return hash($algo, $data);
}

function legacy_digest($data) {
    return digest("md5", $data);
}
