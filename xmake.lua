-- Define build modes
add_rules("mode.debug", "mode.release")

-- Add OpenSSL dependency
add_requires("openssl")

-- Define the SNMP++ package
package("snmp++")
    add_deps("cmake")
    add_deps("openssl", { configs = { shared = true } })

    -- Platform-specific linking
    if is_host("windows") then
        add_syslinks("ws2_32", "crypt32")
    end

    -- Specify the source directory
    set_sourcedir("$(projectdir)/snmp_pp")

    on_install(function (package)
        local openssl = package:dep("openssl")
        local configs = {}
        table.insert(configs, "-DCMAKE_BUILD_TYPE=" .. (package:debug() and "Debug" or "Release"))
        table.insert(configs, "-DBUILD_SHARED_LIBS=" .. (package:config("shared") and "ON" or "OFF"))
        table.insert(configs, "-DOPENSSL_ROOT_DIR=" .. openssl:installdir())

        -- Set the build directory
        local build_dir = os.projectdir() .. "/snmp_pp/build"
        os.mkdir(build_dir)
        import("package.tools.cmake").install(package, configs, {buildir = build_dir})
    end)
package_end()

-- Add the SNMP++ package as a requirement
add_requires("snmp++")

-- Define the AGENT++ package
package("agent++")
    add_deps("cmake")
    add_deps("openssl", { configs = { shared = true } })
    add_deps("snmp++")

    -- Platform-specific linking
    if is_host("windows") then
        add_syslinks("ws2_32", "crypt32")
    end

    -- Specify the source directory
    set_sourcedir("$(projectdir)/agent_pp")
    
    on_install(function (package)
        local openssl = package:dep("openssl")
        local snmp_pp = package:dep("snmp++")
        local configs = {}
        table.insert(configs, "-DCMAKE_BUILD_TYPE=" .. (package:debug() and "Debug" or "Release"))
        table.insert(configs, "-DBUILD_SHARED_LIBS=" .. (package:config("shared") and "ON" or "OFF"))
        table.insert(configs, "-DOPENSSL_ROOT_DIR=" .. openssl:installdir())
        table.insert(configs, "-DSNMP_PP_ROOT_DIR=" .. snmp_pp:installdir())

        -- Set the build directory
        local build_dir = os.projectdir() .. "/agent_pp/build"
        os.mkdir(build_dir)
        import("package.tools.cmake").install(package, configs, {buildir = build_dir})
    end)
package_end()

-- Add the AGENT++ package as a requirement
add_requires("agent++")

target("Project")
    set_kind("binary")
    add_packages("snmp++")
    add_packages("agent++")


    -- -- Include source files and directories
    add_files("$(projectdir)/agent_pp/src/*.cpp")
    add_includedirs("$(projectdir)/agent_pp")
    add_includedirs("$(projectdir)/agent_pp/include")

    add_files("$(projectdir)/snmp_pp/src/*.cpp")
    add_includedirs("$(projectdir)/snmp_pp")
    add_includedirs("$(projectdir)/snmp_pp/include")


    add_files("$(projectdir)/myApp/src/*.cpp")

    add_links("snmp++")
    
    add_links("agent++")