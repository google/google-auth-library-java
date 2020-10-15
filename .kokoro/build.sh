#!/bin/bash
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

cd github/google-auth-library-java/

# Print out Java version
java -version
echo $JOB_TYPE

mvn install -B -V \
  -DskipTests=true \
  -Dclirr.skip \
  -Dmaven.javadoc.skip=true

case ${JOB_TYPE} in
test)
    mvn test -B
    ;;
lint)
    mvn com.coveo:fmt-maven-plugin:check
    ;;
javadoc)
    mvn javadoc:javadoc javadoc:test-javadoc
    ;;
integration)
    mvn -B -pl ${INTEGRATION_TEST_ARGS} -DtrimStackTrace=false -fae verify
    ;;
clirr)
    mvn -B clirr:check
    ;;
*)
    ;;
esac
