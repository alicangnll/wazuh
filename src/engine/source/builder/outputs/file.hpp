/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILE_OUTPUT_H
#define _FILE_OUTPUT_H

#include "rxcpp/rx.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <mutex>

namespace builder::internals::outputs
{

std::mutex lock;

/**
 * @brief implements a subscriber which will save all received events
 * of type E into a file. Needed to implement Destructor to close file.
 *
 *
 */
class FileOutput
{
protected:
    std::ofstream m_os;

public:
    /**
     * @brief Construct a new File Output object
     *
     * @param path file to store the events received
     */
    explicit FileOutput(const std::string & path) : m_os{path, std::ios::out | std::ios::app | std::ios::binary}
    {
        if (!this->m_os)
        {
            throw std::invalid_argument("File output cannot open file " + path);
        }
    }

    /**
     * @brief Closes file if open
     *
     */
    ~FileOutput()
    {
        if (this->m_os.is_open())
        {
            this->m_os.close();
        }
    }

    /**
     * @brief Write event string to file
     *
     * @param e
     */
    void write(const json::Document & e)
    {
        lock.lock();
        this->m_os << e.str() << std::endl;
        lock.unlock();
    }
};

} // namespace builder::internals::outputs

#endif // _FILE_OUTPUT_H
