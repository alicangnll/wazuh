

// TODO: rename files as wazuh style
// TODO: delete dummy test/benchmarks examples, no longer needed
// TODO: QoL CMakeLists
#include "glog/logging.h"
#include <stdexcept>
#include <string>
#include <vector>

#include "Catalog.hpp"
#include "builder.hpp"
#include "catalog/storageDriver/disk/DiskStorage.hpp"
#include "cliParser.hpp"
#include "engineServer.hpp"
#include "graph.hpp"
#include "json.hpp"
#include "register.hpp"
#include "router.hpp"
#include "threadPool.hpp"
#include "protocolHandler.hpp"

using namespace std;

int main(int argc, char * argv[])
{
    google::InitGoogleLogging(argv[0]);
    vector<string> serverArgs;
    string storagePath;
    int nthreads;

    try
    {
        cliparser::CliParser cliInput(argc, argv);
        serverArgs.push_back(cliInput.getEndpointConfig());
        storagePath = cliInput.getStoragePath();
        nthreads = cliInput.getThreads();
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Error while parsing arguments: " << e.what() << endl;
        return 1;
    }

    engineserver::EngineServer server;
    try
    {
        server.configure(serverArgs);
    }
    catch (const exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while configuring server: " << e.what() << endl;
        // TODO: handle if errors on close can happen
        // server.close();
        return 1;
    }

    // hardcoded catalog storage driver
    // TODO: use argparse module
    catalog::Catalog _catalog;
    try
    {
        _catalog.setStorageDriver(make_unique<DiskStorage>(storagePath));
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while configuring catalog: " << e.what() << endl;
        return 1;
    }

    // Builder
    try
    {
        builder::internals::registerBuilders();
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while registering builders: " << e.what() << endl;
        return 1;
    }
    builder::Builder<catalog::Catalog> _builder(_catalog);

    //Handle ThreadPool
    auto sc = rxcpp::schedulers::make_scheduler<threadpool::ThreadPool>(nthreads);
    static rxcpp::observe_on_one_worker r(sc);
    rxcpp::observable<std::shared_ptr<json::Document>>  scheduledTask =
        server.output()
        .map([](std::string s){ return rxcpp::observable<>::just(s); })
        .flat_map([](auto o){
            return o.observe_on(r).map([](std::string s) -> std::shared_ptr<json::Document> {
                        return engineserver::parse(s);
                    });
       });
            

    // Build router
    // TODO: Integrate filter creation with builder and default route with catalog
    router::Router<builder::Builder<catalog::Catalog>> router{scheduledTask, _builder};

    try
    {
        // Default route
        router.add(
            "test_route",
            [](auto j)
            {
                // TODO: check basic fields are present
                return true;
            },
            "test_environment");
    }
    catch (const std::exception & e)
    {
        LOG(ERROR) << "Engine error, got exception while building default route: " << e.what() << endl;
        return 1;
    }

    server.run();

    return 0;
}
