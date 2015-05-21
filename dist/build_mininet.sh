#!/bin/sh

MN_GIT="https://github.com/mininet/mininet.git"
MN_BRANCH="origin/master"

install_mininet() {
    print_status "Installing Mininet"
    $SUPER util/install.sh -fn 
    return 0
}

##
# Fetch and build Mininet from source.
##
build_mininet() {

    fetch "mininet" $MN_GIT $MN_BRANCH ||
        fail "Couldn't fetch Mininet"

    if [ $FETCH_ONLY -ne 1 ]; then
        print_status "Building and Installing Mininet"
        install_mininet || fail "Couldn't install Mininet"
        
        $DO cd -
    fi
}

get_mininet() {
    build_mininet $@
}
