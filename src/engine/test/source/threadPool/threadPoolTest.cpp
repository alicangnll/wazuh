#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <rxcpp/rx-observable.hpp>
#include <glog/logging.h>
#include "threadPool.hpp"

using namespace std::chrono_literals;

TEST(SchedulerTest, ThreadPoolSize)
{

    std::mutex m;
    std::condition_variable cv;
    std::atomic<int> nth = 4;
    std::atomic<int> nsubs = 2;

    std::mutex mtset;
    std::set<std::thread::id> tset;

    using conn_t = rxcpp::observable<int>;
    using oconn_t = rxcpp::observable<std::string>;
    using serv_t = rxcpp::observable<conn_t>;
    // google::InitGoogleLogging();

    auto sc = rxcpp::schedulers::make_scheduler<threadpool::ThreadPool>(nth);

    serv_t server = rxcpp::observable<>::create<conn_t>([](rxcpp::subscriber<conn_t> s ){
        for(int i=0; i < 3; i++) {
            // LOG(INFO) << "NEXT " << std::to_string(i) << " th " << std::this_thread::get_id();
            conn_t a = rxcpp::observable<>::range(1,3);
            s.on_next(a);
        }
        s.on_completed();
    });
    // .observe_on(rxcpp::identity_same_worker(sc.create_worker()))
    auto values = server.flat_map([&](conn_t c){
        return c.observe_on(rxcpp::identity_same_worker(sc.create_worker())
        ).map([](int i) -> std::string { return std::to_string(i); }
        ).tap([](auto s){ 
            // LOG(INFO)  << "TAP     th " <<  std::this_thread::get_id();
        });
    });
    
    for(int i=0; i < nsubs; i++) {
        values.subscribe(
            [&](auto  s){
                mtset.lock();
                tset.insert(std::this_thread::get_id());
                mtset.unlock();
                // LOG(INFO) << "SUB " << std::to_string(i) << " " << s << " th " << std::this_thread::get_id();
            },
            [&, i](){
                std::lock_guard<std::mutex> lk(m);
                nsubs--;
                // LOG(INFO) << "COM " << std::to_string(i) << "   th " << std::this_thread::get_id();
                cv.notify_all();
            });
    }
    std::unique_lock<std::mutex> lock(m);
    cv.wait(lock, [&](){ return nsubs == 0; });
   
    ASSERT_EQ(tset.size(), nth);
}

TEST(SchedulerTest, ThreadPoolRoundRobin)
{

    std::mutex m;
    std::condition_variable cv;
    std::atomic<int> nth = 4;
    std::atomic<int> nsubs = 1;

    std::mutex mtset;
    std::vector<std::thread::id> tset;
    std::thread::id last = std::this_thread::get_id();

    using conn_t = rxcpp::observable<int>;
    using oconn_t = rxcpp::observable<std::string>;
    using serv_t = rxcpp::observable<conn_t>;
    // google::InitGoogleLogging();

    auto sc = rxcpp::schedulers::make_scheduler<threadpool::ThreadPool>(nth);

    serv_t server = rxcpp::observable<>::create<conn_t>([](rxcpp::subscriber<conn_t> s ){
        for(int i=0; i < 3; i++) {
            // LOG(INFO) << "NEXT " << std::to_string(i) << " th " << std::this_thread::get_id();
            conn_t a = rxcpp::observable<>::range(1,3);
            s.on_next(a);
        }
        s.on_completed();
    });
    // .observe_on(rxcpp::identity_same_worker(sc.create_worker()))
    auto values = server.flat_map([&](conn_t c){
        return c.observe_on(rxcpp::identity_same_worker(sc.create_worker())
        ).map([](int i) -> std::string { return std::to_string(i); }
        ).tap([](auto s){ 
            // LOG(INFO)  << "TAP     th " <<  std::this_thread::get_id();
        });
    });
    
    for(int i=0; i < nsubs; i++) {
        values.subscribe(
            [&](auto  s){
                mtset.lock();
                tset.push_back(std::this_thread::get_id());
                mtset.unlock();
                // LOG(INFO) << "SUB " << std::to_string(i) << " " << s << " th " << std::this_thread::get_id();
            },
            [&, i](){
                std::lock_guard<std::mutex> lk(m);
                nsubs--;
                // LOG(INFO) << "COM " << std::to_string(i) << "   th " << std::this_thread::get_id();
                cv.notify_all();
            });
    }
    std::unique_lock<std::mutex> lock(m);
    cv.wait(lock, [&](){ return nsubs == 0; });
   
   // TODO: This test is weak: no two consecutive thread ids should be in the vector of
   // threads when we have only one subscriber, this will mean a round-robin like
   // behaviour, but that's not necesarily true, depending on the scheduler.
    for(auto & id: tset)
    {
        if ( last == id) {
            FAIL();
        }
        last = id;
    }
    SUCCEED();
}
