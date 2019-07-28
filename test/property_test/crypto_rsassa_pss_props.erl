%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(crypto_rsassa_pss_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

digest_type()   -> oneof([md5, sha, sha224, sha256, sha384, sha512, {hmac, md5, <<>>}, {hmac, sha, <<>>}, {hmac, sha224, <<>>}, {hmac, sha256, <<>>}, {hmac, sha384, <<>>}, {hmac, sha512, <<>>}]).
salt_size()     -> non_neg_integer().
modulus_size()  -> integer(1024, 1280). % integer(256, 8192) | pos_integer().
exponent_size() -> return(65537).  % pos_integer().

rsa_keypair(ModulusSize) ->
	?LET(ExponentSize,
		exponent_size(),
		begin
			case public_key:generate_key({rsa, ModulusSize, ExponentSize}) of
				PrivateKey=#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent} ->
					{PrivateKey, #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent}}
			end
		end).

%%====================================================================
%% RSASSA-PSS
%%====================================================================

rsassa_pss_signer_gen() ->
	?LET({DigestType, ModulusSize},
		?SUCHTHAT({DigestType, ModulusSize},
			{digest_type(), modulus_size()},
			ModulusSize >= (bit_size(do_hash(DigestType, <<>>)) * 2 + 16)),
		{rsa_keypair(ModulusSize), ModulusSize, DigestType, binary()}).

rsassa_pss_signer_with_salt_gen() ->
	?LET({DigestType, ModulusSize, SaltSize},
		?SUCHTHAT({DigestType, ModulusSize, SaltSize},
			{digest_type(), modulus_size(), salt_size()},
			ModulusSize >= (bit_size(do_hash(DigestType, <<>>)) + (SaltSize * 8) + 16)),
		{rsa_keypair(ModulusSize), ModulusSize, DigestType, binary(SaltSize), binary()}).

prop_rsassa_pss_sign_and_verify() ->
	?FORALL({{PrivateKey, PublicKey}, _, DigestType, Message},
		rsassa_pss_signer_gen(),
		begin
			{ok, Signature} = crypto_rsassa_pss:rsassa_pss_sign(DigestType, Message, PrivateKey),
			crypto_rsassa_pss:rsassa_pss_verify(DigestType, Message, Signature, PublicKey)
		end).

prop_rsassa_pss_sign_and_verify_with_salt() ->
	?FORALL({{PrivateKey, PublicKey}, _ModulusSize, DigestType, Salt, Message},
		rsassa_pss_signer_with_salt_gen(),
		begin
			{ok, Signature} = crypto_rsassa_pss:rsassa_pss_sign(DigestType, Message, Salt, PrivateKey),
			crypto_rsassa_pss:rsassa_pss_verify(DigestType, Message, Signature, byte_size(Salt), PublicKey)
		end).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

do_hash(DigestType, PlainText) when is_atom(DigestType) ->
	crypto:hash(DigestType, PlainText);
do_hash({hmac, DigestType, Key}, PlainText) ->
	crypto:hmac(DigestType, Key, PlainText).
