PROJECT = crypto_rsassa_pss
TEST_ERLC_OPTS += +'{parse_transform, eunit_autoexport}'
TEST_DEPS = cutkey triq
dep_cutkey = git git://github.com/potatosalad/cutkey.git master
dep_triq = git git://github.com/krestenkrab/triq.git master
include erlang.mk
