/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <chrono>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <testUtils.hpp>
#include <thread>

TEST(RxcppThreading, ObserveOnExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    auto values = rxcpp::observable<>::range(1, 3).map(
        [](int v)
        {
            GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Emit value " << v << endl;
            return v;
        });

    values.observe_on(rxcpp::synchronize_new_thread())
        .as_blocking()
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    values.observe_on(rxcpp::synchronize_new_thread())
        .as_blocking()
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, SubscribeOnExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    auto values = rxcpp::observable<>::range(1, 3).map(
        [](int v)
        {
            GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Emit value " << v << endl;
            return v;
        });
    values.subscribe_on(rxcpp::synchronize_new_thread())
        .as_blocking()
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, MultipleObserveOnExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values = subj.get_observable();
    values.observe_on(rxcpp::synchronize_new_thread())
        .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
        .observe_on(rxcpp::synchronize_new_thread())
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, ObserveOnAfterMultipleOpExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values = subj.get_observable();
    values.tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap1OnNext: " << v << endl; })
        .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap2OnNext: " << v << endl; })
        .observe_on(rxcpp::synchronize_new_thread())
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, SubscribeOnAfterMultipleOpExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values = subj.get_observable();
    values.tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap1OnNext: " << v << endl; })
        .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap2OnNext: " << v << endl; })
        .map(
            [](int v)
            {
                GTEST_COUT << "[thread " << std::this_thread::get_id() << "] MapOnNext: " << v << endl;
                return v;
            })
        .subscribe_on(rxcpp::synchronize_new_thread())
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, SimpleRoundRobin)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;

    struct rrState
    {
        size_t size;
        size_t current;
        size_t next()
        {
            auto ret = current;
            ++current;
            current = current == size ? 0 : current;
            return ret;
        }
        rrState(size_t size) : size{size}, current{0}
        {
        }
    };

    rxcpp::subjects::subject<int> subj1, subj2, subj3;
    auto th1 =
        subj1.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto th2 =
        subj2.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto th3 =
        subj3.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    vector<rxcpp::subscriber<int>> inputs{subj1.get_subscriber(), subj2.get_subscriber(), subj3.get_subscriber()};
    rrState sc(3);
    for (auto i = 0; i < 6; ++i)
    {
        auto j = sc.next();
        GTEST_COUT << "[thread " << std::this_thread::get_id() << "]"
                   << "[" << j << "]Produces " << i << endl;
        inputs[j].on_next(i);
        std::this_thread::sleep_for(chrono::milliseconds(10));
    }

    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Remove Add thread (2)" << endl;
    th3.unsubscribe();
    th3 =
        subj3.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    for (auto i = 0; i < 6; ++i)
    {
        auto j = sc.next();
        GTEST_COUT << "[thread " << std::this_thread::get_id() << "]"
                   << "[" << j << "]Produces " << i << endl;
        inputs[j].on_next(i);
        std::this_thread::sleep_for(chrono::milliseconds(10));
    }
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Add thread (3)" << endl;
    rxcpp::subjects::subject<int> subj4;
    auto th4 =
        subj4.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())

            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    inputs.push_back(subj4.get_subscriber());
    sc.size = 4;
    for (auto i = 0; i < 6; ++i)
    {
        auto j = sc.next();
        GTEST_COUT << "[thread " << std::this_thread::get_id() << "]"
                   << "[" << j << "]Produces " << i << endl;
        inputs[j].on_next(i);
        std::this_thread::sleep_for(chrono::milliseconds(10));
    }
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, ObserveOnWithMiddleSubject)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values =
        subj.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; });

    auto middleSubj = subjects::subject<int>();
    middleSubj.get_observable().subscribe(
        [](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
        []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    values.subscribe(middleSubj.get_subscriber());

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, ThreadFactory)
{
    auto worker = schedulers::worker();
    auto action = schedulers::make_action(
        [](schedulers::schedulable) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Action" << endl; });
    auto loop = schedulers::make_event_loop(
        // This lambda is the thread pool factory
        // f is the task issued by rxcpp
        [](function<void()> f) -> thread
        {
            // Thread pool implementation goes here
            return thread(f);
        });

    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values =
        subj.get_observable()
            .observe_on(identity_same_worker(loop.create_worker()))
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, CustomScheduler)
{
    printsafe("Start task");

    //---------- Get a Coordination
    auto coordination = rxcpp::serialize_new_thread();

    //------- Create a Worker instance through a factory method
    auto worker = coordination.create_coordinator().get_worker();

    //--------- Create a action object
    auto sub_action =
        rxcpp::schedulers::make_action([](const rxcpp::schedulers::schedulable &) { printsafe("Action executed"); });

    //------------- Create a schedulable and schedule the action
    auto scheduled = rxcpp::schedulers::make_schedulable(worker, sub_action);
    scheduled.schedule();

    printsafe("Finish task");
}

TEST(RxcppThreading, CustomSchedulerSchedule)
{
    printsafe("Start task");

    //-------- Create a Coordination function
    auto coordination = rxcpp::identity_current_thread();
    //-------- Instantiate a coordinator and create a worker
    auto worker = coordination.create_coordinator().get_worker();
    //--------- start and the period
    auto start = coordination.now() + std::chrono::milliseconds(1);
    auto period = std::chrono::milliseconds(1);
    //----------- Create an Observable (Replay )
    auto values = rxcpp::observable<>::interval(start, period).take(5).replay(2, coordination);
    //--------------- Subscribe first time using a Worker
    worker.schedule(
        [&](const rxcpp::schedulers::schedulable &) {
            values.subscribe([](long v) { printsafe("1: " + std::to_string(v)); },
                             []() { printsafe("1: OnCompletedn"); });
        });
    worker.schedule(
        [&](const rxcpp::schedulers::schedulable &) {
            values.subscribe([](long v) { printsafe("2: " + std::to_string(v)); },
                             []() { printsafe("2: OnCompletedn"); });
        });
    //----- Start the emission of values
    worker.schedule([&](const rxcpp::schedulers::schedulable &) { values.connect(); });
    //------- Add blocking subscription to see results
    values.as_blocking().subscribe();

    printsafe("Finish task");

    // We created a hot Observable using the replay mechanism to take care of the late subscription by some Observers.
    // We also created a Worker to do the scheduling for subscription and to connect the Observers with the Observable.
    // The previous program demonstrates how the Scheduler works in RxCpp
}
