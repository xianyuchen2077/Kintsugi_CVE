#!/bin/bash
# Run FullTest with proper classpath

cd "$(dirname "$0")"

# Compile if needed
mvn test-compile -q

# Run test
java -cp "target/classes:target/test-classes:$HOME/.m2/repository/net/java/dev/jna/jna/5.14.0/jna-5.14.0.jar" com.syscallfilter.FullTest
