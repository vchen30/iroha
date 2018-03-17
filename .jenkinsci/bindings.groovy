#!/usr/bin/env groovy

def doBindings() {

  def cmake_options = ""
  if (params.JavaBindings) {
    cmake_options += " -DSWIG_JAVA=ON "
  }
  if (params.PythonBindings) {
    cmake_options += " -DSWIG_PYTHON=ON "
  }
  // In case language specific options were not set,
  // build for each language
  if (!params.JavaBindings && !params.PythonBindings) {
    cmake_options += " -DSWIG_JAVA=ON -DSWIG_PYTHON=ON "
  }
  sh """
    JAVA_HOME=/usr/lib/jvm/java-8-oracle cmake \
      -H. \
      -Bbuild \
      -DCMAKE_BUILD_TYPE=Release \
      ${cmake_options}
  """
  sh "JAVA_HOME=/usr/lib/jvm/java-8-oracle cmake --build build --target python_tests"
  sh "cd build; JAVA_HOME=/usr/lib/jvm/java-8-oracle make -j${params.PARALLELISM} irohajava irohapy"
  archive(includes: 'build/shared_model/bindings/')
}

return this
