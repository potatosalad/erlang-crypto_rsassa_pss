%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(crypto_rsassa_pss_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([pkcs1_rsassa_pss_sign_and_verify/1]).
-export([pkcs1_rsassa_pss_sign_and_verify_with_salt/1]).
-export([sign_and_verify/1]).
-export([md5/1]).
-export([sha/1]).
-export([sha224/1]).
-export([sha256/1]).
-export([sha384/1]).
-export([sha512/1]).

all() ->
	[
		{group, '512'},
		{group, '1024'},
		{group, '2048'},
		{group, '4096'},
		{group, '8192'},
		{group, property_test}
	].

groups() ->
	DigestTypes = [
		md5,
		sha,
		sha224,
		sha256,
		sha384,
		sha512
	],
	[
		{'512', [parallel], DigestTypes -- [sha256, sha384, sha512]},
		{'1024', [parallel], DigestTypes -- [sha512]},
		{'2048', [parallel], DigestTypes},
		{'4096', [parallel], DigestTypes},
		{'8192', [parallel], DigestTypes},
		{property_test, [parallel], [
			pkcs1_rsassa_pss_sign_and_verify,
			pkcs1_rsassa_pss_sign_and_verify_with_salt
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(crypto_rsassa_pss),
	ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
	_ = application:stop(crypto_rsassa_pss),
	ok.

init_per_group(G='512', Config) ->
	[{keypair, rsa_keypair(512)} | crypto_rsassa_pss_ct:start(G, Config)];
init_per_group(G='1024', Config) ->
	[{keypair, rsa_keypair(1024)} | crypto_rsassa_pss_ct:start(G, Config)];
init_per_group(G='2048', Config) ->
	[{keypair, rsa_keypair(2048)} | crypto_rsassa_pss_ct:start(G, Config)];
init_per_group(G='4096', Config) ->
	[{keypair, rsa_keypair(4096)} | crypto_rsassa_pss_ct:start(G, Config)];
init_per_group(G='8192', Config) ->
	[{keypair, rsa_keypair(8192)} | crypto_rsassa_pss_ct:start(G, Config)];
init_per_group(G=property_test, Config) ->
	crypto_rsassa_pss_ct:start(G, Config).

end_per_group(_Group, Config) ->
	crypto_rsassa_pss_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

pkcs1_rsassa_pss_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		crypto_rsassa_pss_props:prop_rsassa_pss_sign_and_verify(),
		Config).

pkcs1_rsassa_pss_sign_and_verify_with_salt(Config) ->
	ct_property_test:quickcheck(
		crypto_rsassa_pss_props:prop_rsassa_pss_sign_and_verify_with_salt(),
		Config).

sign_and_verify(Config) ->
	DigestType = ?config(digest_type, Config),
	{PrivateKey, PublicKey} = ?config(keypair, Config),
	Message = crypto:strong_rand_bytes(random_uniform(256, 1024)),
	Signature = crypto_rsassa_pss:sign(Message, DigestType, PrivateKey),
	NextSignature = crypto_rsassa_pss:sign(Message, DigestType, PrivateKey),
	false = (Signature =:= NextSignature),
	true = crypto_rsassa_pss:verify(Message, DigestType, Signature, PublicKey),
	true = crypto_rsassa_pss:verify(Message, DigestType, NextSignature, PublicKey),
	ok.

md5(Config) ->
	sign_and_verify([{digest_type, md5} | Config]).

sha(Config) ->
	sign_and_verify([{digest_type, sha} | Config]).

sha224(Config) ->
	sign_and_verify([{digest_type, sha224} | Config]).

sha256(Config) ->
	sign_and_verify([{digest_type, sha256} | Config]).

sha384(Config) ->
	sign_and_verify([{digest_type, sha384} | Config]).

sha512(Config) ->
	sign_and_verify([{digest_type, sha512} | Config]).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
random_uniform(High) when is_integer(High) andalso High >= 0 ->
	rand:uniform(High + 1) - 1.

%% @private
random_uniform(0, High) when is_integer(High) andalso High >= 0 ->
	random_uniform(High);
random_uniform(Low, High) when is_integer(Low) andalso Low > 0 andalso is_integer(High) andalso High >= 0 ->
	rand:uniform(High - Low + 1) + Low - 1.

rsa_keypair(ModulusSize) ->
	ExponentSize = 65537,
	case public_key:generate_key({rsa, ModulusSize, ExponentSize}) of
		PrivateKey=#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent} ->
			{PrivateKey, #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent}}
	end.
