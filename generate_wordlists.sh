#!/bin/bash
set -e
java -jar build/libs/GadgetProbe-1.0-SNAPSHOT-all.jar > wordlists/gadgetprobe_analyzer_classes.list
curl "https://raw.githubusercontent.com/FasterXML/jackson-databind/master/src/main/java/com/fasterxml/jackson/databind/jsontype/impl/SubTypeValidator.java" | sed -n -e 's/^\s*s.add("\(.*\)");/\1/p' > wordlists/FasterXML_blacklist.list
