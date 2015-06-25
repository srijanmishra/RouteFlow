#!/bin/sh

MAVEN_URL="http://archive.apache.org/dist/maven/maven-3/3.3.1/binaries"
MAVEN_VERSION="3.3.1"

KARAF_URL="http://download.nextag.com/apache/karaf/3.0.3"
KARAF_VERSION="3.0.3"

ONOS_URL="https://gerrit.onosproject.org/onos"
ONOS_GIT="https://gerrit.onosproject.org/onos"
ONOS_BRANCH="origin/master"

##
# Fetch and build ONOS source.
#
# $1 - Version string or "git"
##
build_onos() {
    if [ -e "onos-$1" ] && [ $UPDATE -eq 0 ]; then
        return;
    fi

    fetch "onos" "git" $ONOS_GIT $ONOS_BRANCH $ONOS_URL ||
        fail "Couldn't fetch OVS"

    if [ $FETCH_ONLY -ne 1 ]; then
        print_status "Installing ONOS"
        export ONOS_ROOT=`pwd`
        source $ONOS_ROOT/tools/dev/bash_profile
        mvn clean install
        $DO cd -
    fi
}

build_karaf() {
    if [ -e "apache-karaf-$KARAF_VERSION" ] && [ $UPDATE -eq 0 ]; then
        return;
    fi

    print_status "Fetching Apache Karaf"
    fetch "apache-karaf-" $KARAF_VERSION "" "" $KARAF_URL ||
        fail "Couldn't fetch Apache Karaf"

    $SUPER export PATH="$RFDIR/apache-karaf-3.0.3/bin:$PATH"
    $SUPER export KARAF_HOME="$RFDIR/apache-karaf-3.0.3/"
    $SUPER export KARAF_DATA="$RFDIR/apache-karaf-3.0.3/data"
    $SUPER export KARAF_ETC="$RFDIR/apache-karaf-3.0.3/etc"
}

build_maven() {
    if [ -e "apache-maven-$MAVEN_VERSION" ] && [ $UPDATE -eq 0 ]; then
        return;
    fi

    print_status "Fetching Apache Maven"
    fetch "apache-karaf-" $MAVEN_VERSION "" "" $MAVEN_URL ||
        fail "Couldn't fetch Apache Maven"

    $SUPER export PATH="$RFDIR/apache-mave-3.3.3/bin:$PATH"
    
}

build_java() {
    pkg_install "software-properties-common -y"
    $SUPER add-apt-repository ppa:webupd8team/java -y
    $SUPER apt-get update
    pkg_install "oracle-java8-installer oracle-java8-set-default -y"

    $SUPER export JAVA_HOME=/usr/lib/jvm/java-8-oracle
}

get_onos() {
    build_java $@
    build_karaf $@
    build_maven $@ 
    build_onos $@
}
