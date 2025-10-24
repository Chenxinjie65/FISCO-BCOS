/**
 * @CopyRight:
 * FISCO-BCOS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FISCO-BCOS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FISCO-BCOS.  If not, see <http://www.gnu.org/licenses/>
 * (c) 2016-2018 fisco-dev contributors.
 *
 * @brief: empty framework for main of FISCO-BCOS
 *
 * @file: main.cpp
 * @author: yujiechen
 * @date 2018-08-24
 */
#include "Common.h"
#include <include/BuildInfo.h>
#include <libdevcore/Common.h>
#include <libdevcore/FileSignal.h>
#include <libinitializer/Initializer.h>
#include <boost/program_options.hpp>
#include <clocale>
#include <iostream>
#include <memory>
#include <thread>
#include <execinfo.h>  
#include <libdevcore/Log.h>  

using namespace std;
using namespace dev;
using namespace dev::initializer;

/**
 * @brief 获取当前函数调用栈
 * @return 调用栈
 */
inline std::string getStackTrace()
{
    const int MAX_FRAMES = 100;
    void* frames[MAX_FRAMES];
    int frameCount = backtrace(frames, MAX_FRAMES);
    char** frameStrings = backtrace_symbols(frames, frameCount);
    
    std::string stackTrace;
    stackTrace += "\n=== Start Stack Trace ===\n";
    
    for (int i = 0; i < frameCount; i++)
    {
        stackTrace += "Frame " + std::to_string(i) + ": " + frameStrings[i] + "\n";
    }
    
    stackTrace += "=== End Stack Trace ===\n";
    free(frameStrings);
    return stackTrace;
}

void checkAndCall(const std::string& configPath, shared_ptr<Initializer> initializer)
{
    std::string moreGroupSignal = configPath + ".append_group";
    dev::FileSignal::callIfFileExist(moreGroupSignal, [&]() {
        cout << "Start more group" << endl;
        initializer->ledgerInitializer()->startMoreLedger();
    });

    std::string resetCalSignal = configPath + ".reset_certificate_whitelist";
    dev::FileSignal::callIfFileExist(resetCalSignal, [&]() {
        cout << "Reset certificate whitelist(CAL)" << endl;
        initializer->p2pInitializer()->resetWhitelist(configPath);
    });
    std::string resetSDKAllowListSignal = configPath + ".reset_allowlist";
    dev::FileSignal::callIfFileExist(resetSDKAllowListSignal, [&]() {
        cout << "Reset sdk allowList(public keys)" << endl;
        initializer->ledgerInitializer()->reloadSDKAllowList();
    });
}

int main(int argc, const char* argv[])
{
    /// set LC_ALL
    setDefaultOrCLocale();
    std::set_terminate([]() {
        std::cerr << "terminate handler called" << endl;
        abort();
    });
    // get datetime and output welcome info
    ExitHandler exitHandler;
    signal(SIGTERM, &ExitHandler::exitHandler);
    signal(SIGABRT, &ExitHandler::exitHandler);
    signal(SIGINT, &ExitHandler::exitHandler);
    /// callback initializer to init all ledgers
    auto initialize = std::make_shared<Initializer>();
    std::string configPath("./config.ini");
    try
    {
        /// init params
        configPath = initCommandLine(argc, argv);
        std::cout << "[" << getCurrentDateTime() << "] ";
        std::cout << "Initializing..." << std::endl;
        
        LOG(INFO) << LOG_BADGE("StackTrace") << LOG_DESC("Node initialization started") 
                  << "\n" << getStackTrace();
        
        initialize->init(configPath);
        
        LOG(INFO) << LOG_BADGE("StackTrace") << LOG_DESC("Node initialization completed") 
                  << "\n" << getStackTrace();
    }
    catch (std::exception& e)
    {
        std::cerr << "Init failed!!!" << std::endl;
        LOG(ERROR) << LOG_BADGE("StackTrace") << LOG_DESC("Node initialization failed") 
                   << LOG_KV("error", e.what()) << "\n" << getStackTrace();
        return -1;
    }
    dev::version();
    std::cout << "[" << getCurrentDateTime() << "] ";
    std::cout << "The FISCO-BCOS is running..." << std::endl;
    
    LOG(INFO) << LOG_BADGE("StackTrace") << LOG_DESC("Node startup completed") 
              << "\n" << getStackTrace();

    while (!exitHandler.shouldExit())
    {
        checkAndCall(configPath, initialize);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    initialize.reset();
    std::cout << "[" << getCurrentDateTime() << "] ";
    std::cout << "FISCO-BCOS program exit normally." << std::endl;

    return 0;
}
