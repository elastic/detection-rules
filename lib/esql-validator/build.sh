#!/usr/bin/env bash
# Build the esql-validator daemon JAR by reusing the elasticsearch x-pack-esql
# compiled classpath. Requires:
#   - An elasticsearch checkout at $ES_HOME (default: /tmp/elasticsearch).
#   - A JDK 21+ on $PATH (and $RUNTIME_JAVA_HOME exported, per ES convention).
#
# Output (paths relative to this script):
#   build/esql-validator.jar   — our compiled daemon, manifest Main-Class set.
#   build/classpath.txt        — colon-separated classpath of all ES jars needed
#                                to run the daemon. Pass with `java -cp`.
#
# The whole build is cached: re-running with the same ES checkout and unchanged
# sources is fast (gradle hits its build cache, javac re-runs only if .java
# files changed).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ES_HOME="${ES_HOME:-/tmp/elasticsearch}"
BUILD_DIR="$SCRIPT_DIR/build"

if [[ ! -x "$ES_HOME/gradlew" ]]; then
  echo "error: ES_HOME=$ES_HOME does not contain a gradlew script." >&2
  exit 1
fi
if ! command -v javac >/dev/null 2>&1; then
  echo "error: javac not found on PATH. Install JDK 21 and re-run." >&2
  exit 1
fi

mkdir -p "$BUILD_DIR"

# Init script: registers a one-shot task `drPrintRuntimeClasspath` on
# :x-pack:plugin:esql that prints the full runtime classpath in a
# greppable form.
INIT_SCRIPT="$BUILD_DIR/print-classpath.init.gradle"
cat > "$INIT_SCRIPT" <<'GRADLE'
allprojects {
  afterEvaluate { proj ->
    if (proj.path == ':x-pack:plugin:esql') {
      proj.tasks.register('drPrintRuntimeClasspath') {
        // We use compileClasspath rather than runtimeClasspath here because
        // xpack-core, lang-painless and friends are declared `compileOnly` in
        // ES (they're loaded as plugins at runtime). For a standalone JVM we
        // need them on the classpath ourselves.
        dependsOn proj.tasks.named('jar')
        dependsOn ':x-pack:plugin:core:jar'
        dependsOn ':modules:lang-painless:jar'
        dependsOn ':x-pack:plugin:ml:jar'
        doLast {
          def files = [] as Set
          files.addAll(proj.configurations.compileClasspath.files)
          files.addAll(proj.configurations.runtimeClasspath.files)
          files.add(proj.tasks.named('jar').get().archiveFile.get().asFile)
          println 'DR_CLASSPATH_BEGIN'
          files.collect { it.absolutePath }.toSet().sort().each { println 'DR_CP::' + it }
          println 'DR_CLASSPATH_END'
        }
      }
    }
  }
}
GRADLE

echo ">> Building x-pack-esql plugin in $ES_HOME (first build can be slow)…" >&2
(
  cd "$ES_HOME"
  ./gradlew --console=plain --warning-mode=none -q \
      :x-pack:plugin:esql:jar \
      :x-pack:plugin:esql:drPrintRuntimeClasspath \
      --init-script "$INIT_SCRIPT"
) > "$BUILD_DIR/gradle-classpath.out" 2> "$BUILD_DIR/gradle-classpath.err" || {
  echo "error: gradle invocation failed. See:" >&2
  echo "  $BUILD_DIR/gradle-classpath.err" >&2
  tail -n 40 "$BUILD_DIR/gradle-classpath.err" >&2 || true
  exit 1
}

# Extract jar paths between the markers and join with ':'.
CP=$(awk '/^DR_CLASSPATH_BEGIN$/{flag=1; next} /^DR_CLASSPATH_END$/{flag=0} flag && /^DR_CP::/{sub("^DR_CP::",""); print}' \
        "$BUILD_DIR/gradle-classpath.out" | paste -sd: -)
if [[ -z "$CP" ]]; then
  echo "error: no classpath captured from gradle output. See $BUILD_DIR/gradle-classpath.out" >&2
  exit 1
fi

echo "$CP" > "$BUILD_DIR/classpath.txt"
echo ">> Resolved $(echo "$CP" | tr ':' '\n' | wc -l) classpath entries → build/classpath.txt" >&2

# Compile daemon sources.
CLASSES_DIR="$BUILD_DIR/classes"
rm -rf "$CLASSES_DIR"
mkdir -p "$CLASSES_DIR"

echo ">> Compiling daemon sources…" >&2
find "$SCRIPT_DIR/src/main/java" -name "*.java" > "$BUILD_DIR/sources.txt"
javac --release 21 -cp "$CP" -d "$CLASSES_DIR" @"$BUILD_DIR/sources.txt"

# Build the jar.
MANIFEST="$BUILD_DIR/manifest.mf"
{
  echo "Manifest-Version: 1.0"
  echo "Main-Class: co.elastic.detectionrules.esqlvalidator.Main"
} > "$MANIFEST"

JAR_FILE="$BUILD_DIR/esql-validator.jar"
(cd "$CLASSES_DIR" && jar cfm "$JAR_FILE" "$MANIFEST" .)
echo ">> Built $JAR_FILE" >&2
echo ">> Run with: java -cp \"\$(cat $BUILD_DIR/classpath.txt):$JAR_FILE\" co.elastic.detectionrules.esqlvalidator.Main" >&2
