file(GLOB RNSH_SRCS "src/*.cpp")

include(${CMAKE_CURRENT_LIST_DIR}/spangap_requires.cmake)
# Conditional sources: esp-idf/conditional/<name>/ is compiled only when <name>
# is staged (none yet — the settings pane is generated from straddle.yaml).
idf_component_register(
    SRCS ${RNSH_SRCS} ${SPANGAP_CONDITIONAL_SRCS}
    INCLUDE_DIRS "include" ${SPANGAP_CONDITIONAL_INCLUDE_DIRS}
    REQUIRES
        ${SPANGAP_REQUIRES}
)
