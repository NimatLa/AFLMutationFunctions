/*! \file
Declares the CAFLMutationFunctions class.

The CAFLMutationFunctions class implements the AFL mutation operations.
The purpose is to make the operations more reusable.
*/

#pragma once

#include <cstdint>
#include <random>
#include <vector>
#include <typeindex>
#include <span>
#include <functional>
#include <concepts>

#include "AlignmentSafeReference.hh"

namespace AFLMutationFunctions
{
	//! A class that implements the AFL mutation operations.
	class CAFLMutationFunctions
	{

	// Public interface.
	public:

		using byte = uint8_t;

		//! Constructor.
		CAFLMutationFunctions();

		//! Seeds the random number generation.
		void Seed( uint32_t ui32Seed );

		//! Applies a number of havoc mutations.
		size_t Havoc(
			byte* pui8Buffer,  //!< Buffer that is mutated.
			size_t size,  //!< Size of the data in the buffer.
			size_t sizeMax  //!< Maximum size of the mutated data that fits in the buffer.
		);

		//! Flips a random bit in the buffer.
		size_t FlipBit(
			byte* pui8Buffer,  //!< Buffer that is mutated.
			size_t size  //!< Size of the buffer.
		);

		//! Replaces an integer of specified length with an interesting value. Randomly chooses endian.
		template<std::integral T>
		size_t InterestingValue(
			uint8_t* pui8Buffer,  //!< Buffer that is mutated.
			size_t size  //!< Size of the buffer.
		);

		//! Adds a random value to an iteger in the buffer.
		template<class T>
		size_t ArithmeticAdd(
			uint8_t* pui8Buffer,  //!< Buffer that is mutated.
			size_t size  //!< Size of the buffer.
		);

		//! Substracts a random value from an iteger in the buffer.
		template<class T>
		size_t ArithmeticSubstract(
			uint8_t* pui8Buffer,  //!< Buffer that is mutated.
			size_t size  //!< Size of the buffer.
		);

		//! Replaces a byte in the buffer with a random value.
		size_t RandomByteReplace(
			uint8_t* pui8Buffer,  //!< Buffer that is mutated.
			size_t size  //!< Size of the buffer.
		);

		//! Removes a random sized block from the buffer.
		size_t RemoveRandomBlock(
			uint8_t* pui8Buffer,  //!< Buffer that is mutated.
			size_t size  //!< Size of the buffer.
		);

		//! Inserts a block to the buffer using either a cloned block or repeated random byte.
		size_t RandomBlockInsert(
			uint8_t* pui8Buffer,  //!< Buffer that is mutated.
			size_t size,  //!< Size of the data in the buffer.
			size_t sizeMax  //!< Maximum size of the data that fits in the buffer.
		);

		//! Overwrites a block in the buffer with either a cloned block or repeated random byte.
		size_t RandomChunkOverwrite(
			uint8_t* pui8Buffer,  //!< Buffer that is mutated.
			size_t size  //!< Size of the buffer.
		);

	// Public data.
	public:

		const size_t MUTATION_FAILED = -1;  //!< Value returned by mutation functions if mutation fails.

	// Protected interface.
	protected:

		//! Returns a span of interesting values.
		std::span<const size_t> GetInterestingValues(
			const std::type_index& type  //!< Type of the interesting values.
		);

		//! Returns the number of hacov operations that are done in a call to Havoc.
		unsigned int StackedHavocOperationsCount();

		//! Randomly chooses an integer from a range.
		size_t RandomPosition(
			size_t sizeMinimumInclusive,  //!< Minimum value in the range.
			size_t sizeMaximumInclusive  //!< Maximum value in the range.
		);

		//! Chooses a random position in a buffer that can fit a block of specified size.
		inline size_t ChooseIndexOfRandomBlock(
			uint8_t* pui8Buffer,  //!< Buffer to choose from.
			size_t size,  //!< Size of the buffer.
			size_t sizeBlock  //!< Size of the block.
		);

		//! Chooses a random position in a buffer and returns an iteger reference to that position.
		template<class T>
		inline CAlignmentSafeReference< T > ChooseRandomValueReference(
			uint8_t* pui8Buffer,  //!< Buffer to choose from.
			size_t size  //!< Size of the buffer.
		);

	// Protected data.
	protected:

		//! Type of mutation operations used in Havoc.
		using MutationOperation = size_t(
			CAFLMutationFunctions*,
			uint8_t* pui8Buffer,
			size_t size,
			size_t sizeMax
		);
		using MutationFunction = std::function<MutationOperation>;
		std::vector<MutationFunction> m_vecHavocOperationsConstSize;  //<! Callbacks to mutation operations used in havoc.
		std::vector<MutationFunction> m_vecHavocOperationsSizeIncrease;

		// Constants.
		const unsigned int MAX_FAILED_MUTATIONS = 128;
		const size_t ARITHMETIC_MAX = 35;

		std::default_random_engine m_randomengine;  //!< Random number engine.

	// Private data.
	private:

		std::vector<size_t> m_vecInterestingInts;  //!< Interesting integers.
		size_t m_uiIteresting8Bit; //!< Number of interesting 8 bit integers.
		size_t m_uiIteresting16Bit; //!< Number of interesting 16 bit integers.
		size_t m_uiIteresting32Bit; //!< Number of interesting 32 bit integers.
		size_t m_uiIteresting64Bit; //!< Number of interesting 64 bit integers.
	};
}