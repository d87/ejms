ERL = erl -boot start_clean 

MODS=ejms \
	ejms_sup \
	ejms_worker \
	ejms_db \
	ejms_app \
	ejms_pool_srv \
	ejms_pool_sup \
	ejms_pool_sup_sup \
	ejms_pool \
	pop3

EBIN_FILES=$(addprefix ebin/,${MODS:%=%.beam})

all: compile

ebin/%.beam : src/%.erl
	erlc -W -o ebin/ $<

compile: ${EBIN_FILES}

clean:	
	rm -rf ebin/*.beam erl_crash.dump
