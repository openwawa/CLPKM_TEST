#ifndef __DURATION_H
#define __DURATION_H

//#include "os.hpp"

#include <iostream>

#include <chrono>

class CDuration
{
protected:

	std::chrono::time_point<std::chrono::high_resolution_clock> m_begin;
	double m_elapsed;

public:
	inline CDuration(void)
	{
		m_begin = std::chrono::high_resolution_clock::now();
	}

	inline void Reset()
	{
		m_begin = std::chrono::high_resolution_clock::now();
	}

	inline void Start(void)
	{
		Reset();
	}

	inline void Stop(void)
	{
		m_elapsed = double(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - m_begin).count());
	}

	inline double GetDuration(void)
	{
		Stop();
		return m_elapsed;
	}
};

#define MEASURE_TIME(func)		{CDuration timer;timer.Start();func;timer.Stop();std::cout << "Line: " << __LINE__ << " costs: " << timer.GetDuration() << " us." << std::endl;};

#endif