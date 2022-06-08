/*! \file
Implementation of the CAFLMutationFunctions.

Original AFL mutation algorithms written by Michal Zalewski <lcamtuf@google.com>
No source code reused.
*/

#include "AFLMutationFunctions.hh"
#include <cstring>
#include <limits>
#include <random>
#include <cassert>
#include <stdexcept>

#include "VectorConcatenation.hh"

template<class T>
T SwapEndian(
	T value
);

//! Swap the endianness of a value.
template<>
uint8_t SwapEndian(
	uint8_t ui8Value  //!< Value whose endianness is swapped.
)
{
	// Single byte values are the same in both endiands.
	return ui8Value;
}

//! Swap the endianness of a value.
template<>
uint16_t SwapEndian(
	uint16_t ui16Value  //!< Value whose endianness is swapped.
)
{
	return _byteswap_ushort( ui16Value );
}

//! Swap the endianness of a value.
template<>
uint32_t SwapEndian(
	uint32_t ui32Value  //!< Value whose endianness is swapped.
)
{
	return _byteswap_ulong( ui32Value );
}

//! Swap the endianness of a value.
template<>
uint64_t SwapEndian(
	uint64_t ui64Value  //!< Value whose endianness is swapped.
)
{
	return _byteswap_uint64( ui64Value );
}

//! Adds other endian values to a vector of interesting values.
template<class T>
void AddOtherEndian(
	std::vector<T>& vecInteresting
)
{
	// Insert the swapped endian value of every current value.
	vecInteresting.reserve( vecInteresting.size() * 2 );
	size_t sizeItems = vecInteresting.size();
	for( int i = 0; i < sizeItems; i++ )
		vecInteresting.push_back( SwapEndian<typename std::make_unsigned<T>::type>( static_cast<typename std::make_unsigned<T>::type>( vecInteresting[ i ] ) ) );
}

namespace AFLMutationFunctions
{

//! Constructor.
CAFLMutationFunctions::CAFLMutationFunctions()
{
	std::vector<int8_t> vecInteresting8Bit =
	{
		std::numeric_limits<int8_t>::min(),
		-1,
		0,
		1,
		16,
		32,
		100,
		std::numeric_limits<int8_t>::max(),
	};

	std::vector<int16_t> vecInteresting16Bit =
	{
		std::numeric_limits<int16_t>::min(),
		std::numeric_limits<int8_t>::min() - 1,
		std::numeric_limits<int8_t>::max() + 1,
		std::numeric_limits<uint8_t>::max(),
		std::numeric_limits<uint8_t>::max() + 1,
		1 << 9,
		1000,
		1 << 10,
		1 << 12,
		std::numeric_limits<int16_t>::min(),
	};

	std::vector<int32_t> vecInteresting32Bit =
	{
		std::numeric_limits<int32_t>::min(),
		100663046,  // Large negative number (endian-agnostic).
		std::numeric_limits<int16_t>::min() - 1,
		std::numeric_limits<int16_t>::max() + 1,
		std::numeric_limits<uint16_t>::max(),
		std::numeric_limits<uint16_t>::max() + 1,
		100663045,  // Large positive number (endian-agnostic).
		std::numeric_limits<int32_t>::max(),
	};

	std::vector<int64_t> vecInteresting64Bit =
	{
		std::numeric_limits<int64_t>::min(),
		std::numeric_limits<int32_t>::min() - 1ll,
		std::numeric_limits<int32_t>::max() + 1ll,
		std::numeric_limits<uint32_t>::max(),
		std::numeric_limits<uint32_t>::max() + 1ll,
		std::numeric_limits<int64_t>::max(),
	};

	// AFL interesting values -mutation operations have 50-50 chance of using big or small endian.
	// Rather than calculating the inverted endian while running, precalculate them here.
	AddOtherEndian( vecInteresting16Bit );
	AddOtherEndian( vecInteresting32Bit );
	AddOtherEndian( vecInteresting64Bit );

	// Store all the interesting values to a vector.
	for( int8_t i : vecInteresting8Bit )
		m_vecInterestingInts.push_back( static_cast<size_t>( i ) );
	for( int16_t i : vecInteresting16Bit )
		m_vecInterestingInts.push_back( static_cast<size_t>( i ) );
	for( int32_t i : vecInteresting32Bit )
		m_vecInterestingInts.push_back( static_cast<size_t>( i ) );
	for( int64_t i : vecInteresting64Bit )
		m_vecInterestingInts.push_back( static_cast<size_t>( i ) );

	// Save the number of interesting integers.
	m_uiIteresting8Bit = vecInteresting8Bit.size();
	m_uiIteresting16Bit = vecInteresting16Bit.size();
	m_uiIteresting32Bit = vecInteresting32Bit.size();
	m_uiIteresting64Bit = vecInteresting64Bit.size();

	// Set the mutation operations for havoc.
	using namespace std::placeholders;
	m_vecHavocOperationsConstSize =
	{
		std::bind( &CAFLMutationFunctions::FlipBit, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::InterestingValue<uint8_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::InterestingValue<uint16_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::InterestingValue<uint32_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::InterestingValue<uint64_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticSubstract<uint8_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticSubstract<uint16_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticSubstract<uint32_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticSubstract<uint64_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticAdd<uint8_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticAdd<uint16_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticAdd<uint32_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::ArithmeticAdd<uint64_t>, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::RandomByteReplace, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::RemoveRandomBlock, _1, _2, _3 ),
		// Reducing test case size is made more likely than increasing so that test cases remain reasonably sized.
		std::bind( &CAFLMutationFunctions::RemoveRandomBlock, _1, _2, _3 ),
		std::bind( &CAFLMutationFunctions::RandomChunkOverwrite, _1, _2, _3 )
	};
	m_vecHavocOperationsSizeIncrease =
	{
		&CAFLMutationFunctions::RandomBlockInsert,
	};
}

// Seeds the random number generation.
void CAFLMutationFunctions::Seed( uint32_t seed ) { m_randomengine.seed( seed ); }

//! Applies a number of havoc mutations.
size_t CAFLMutationFunctions::Havoc(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size,  //!< Size of the data in the buffer.
	size_t sizeMax  //!< Maximum size of the mutated data that fits in the buffer.
)
{
	// Check that the size can be mutated.
	if( size < 0 || size > sizeMax || ( size == 0 && sizeMax == 0 ) )
		throw std::invalid_argument( "Invalid buffer size for havoc." );

	// Mutate the field using a random number of mutations.
	size_t sizeNew = size;
	unsigned int uiHavocIterations = StackedHavocOperationsCount();
	unsigned int uiIterationsWithErrors = 0;
	CVectorConcatenation<MutationFunction> vcmfPossibleMutations;
	for( int i = 0; i < uiHavocIterations; i++ )
	{
		// Get the possible mutation operations according to size constraints.
		vcmfPossibleMutations.Clear();
		if( sizeMax > sizeNew )
		{
			// Size can increase. This should also cover situation where sizeNew == 0.

			// Use mutation operations that can increase the size.
			vcmfPossibleMutations.Concatenate( &m_vecHavocOperationsSizeIncrease );
		}
		if( sizeNew != 0 )
		{
			// There is some data to mutate.

			// Use the constant size mutations.
			vcmfPossibleMutations.Concatenate( &m_vecHavocOperationsConstSize );
		}

		// Get a random mutation function.
		size_t sizeOperationIndex = RandomPosition( 0, vcmfPossibleMutations.Size() - 1 );
		const MutationFunction& funcOperation = vcmfPossibleMutations[ sizeOperationIndex ];

		// Invoke the random mutation function.
		size_t sizeBeforeMutation = sizeNew;
		sizeNew = funcOperation( this, pui8Buffer, sizeNew, sizeMax );

		// Do not count iterations where mutation fails.
		// The buffer may not have been large enough, for example.
		if( sizeNew == MUTATION_FAILED )
		{
			sizeNew = sizeBeforeMutation;
			i--;

			// Throw an exception if the maximum number of failed mutations was exceeded.
			if( ++uiIterationsWithErrors >= MAX_FAILED_MUTATIONS )
				throw std::exception( "AFL Havoc hung because of failing operations." );
		}
		else
			uiIterationsWithErrors = 0;
	}

	return sizeNew;
}

//! Flips a random bit in the buffer.
size_t CAFLMutationFunctions::FlipBit(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size  //!< Size of the buffer.
)
{
	// This function cannot reduce size.
	if( size <= 0 )
		return MUTATION_FAILED;

	// Select a random byte and xor a random bit.
	CAlignmentSafeReference asrRandomByte = ChooseRandomValueReference<uint8_t>( pui8Buffer, size );
	asrRandomByte.Set( asrRandomByte.Get() ^ ( 1 << RandomPosition( 0, 7 ) ) );

	return size;
}

//! Returns a span of interesting values.
std::span<const size_t> CAFLMutationFunctions::GetInterestingValues(
	const std::type_index& type  //!< Type of the interesting values.
)
{
	if( type == std::type_index( typeid( uint8_t ) ) )
		return std::span<const size_t>( m_vecInterestingInts ).first( m_uiIteresting8Bit );
	else if( type == std::type_index( typeid( uint16_t ) ) )
		return std::span<const size_t>( m_vecInterestingInts ).first( m_uiIteresting16Bit );
	else if( type == std::type_index( typeid( uint32_t ) ) )
		return std::span<const size_t>( m_vecInterestingInts ).first( m_uiIteresting32Bit );
	else if( type == std::type_index( typeid( uint64_t ) ) )
		return std::span<const size_t>( m_vecInterestingInts ).first( m_uiIteresting64Bit );
	else
		throw std::invalid_argument( "This type does not have interesting values: " + std::string( type.name() ) );
}

//! Returns the number of hacov operations that are done in a call to Havoc.
unsigned int CAFLMutationFunctions::StackedHavocOperationsCount()
{
	constexpr double maxPower = 5;  // 2^5 = 32 iterations.
	return std::pow( 2, std::uniform_real_distribution<double>( 0., maxPower )( m_randomengine ) );
}

//! Replaces an integer of specified length with an interesting value. Randomly chooses endian.
template<class T>
size_t CAFLMutationFunctions::InterestingValue(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size  //!< Size of the buffer.
)
{
	// Check if size is ok.
	if( size < sizeof( T ) )
		return MUTATION_FAILED;

	// Get the correct type of interesting values.
	const std::span<const size_t> spanInteresting = GetInterestingValues( typeid( T ) );

	// Set random integer in the buffer to an interesting value.
	CAlignmentSafeReference valueInBuffer = ChooseRandomValueReference<T>( pui8Buffer, size );
	valueInBuffer.Set( static_cast<T>( spanInteresting[ RandomPosition( 0, spanInteresting.size() - 1 ) ] ) );

	return size;
}

//! Adds a random value to an iteger in the buffer.
template<class T>
size_t CAFLMutationFunctions::ArithmeticAdd(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size  //!< Size of the buffer.
)
{
	// Check if size is ok.
	if( size < sizeof( T ) )
		return MUTATION_FAILED;

	// Get a random value that will be added to a value in the buffer.
	T randomValue = RandomPosition( 1, this->ARITHMETIC_MAX );
	
	// Randomly swap the endian of the value.
	if( sizeof( T ) >= 2 && RandomPosition( 0, 1 ) == 1 )
		randomValue = SwapEndian<T>( randomValue );

	// Add the random value to a random integer in the buffer.
	CAlignmentSafeReference valueInBuffer = ChooseRandomValueReference<T>( pui8Buffer, size );
	valueInBuffer.Set( valueInBuffer.Get() + randomValue );

	return size;
}

//! Substracts a random value from an iteger in the buffer.
template<class T>
size_t CAFLMutationFunctions::ArithmeticSubstract(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size  //!< Size of the buffer.
)
{
	// Check if size is ok.
	if( size < sizeof( T ) )
		return MUTATION_FAILED;

	// Get a random value that will be substracted from a value in the buffer.
	T randomValue = RandomPosition( 1, this->ARITHMETIC_MAX );
	
	// Randomly swap the endian of the value.
	if( sizeof( T ) >= 2 && RandomPosition( 0, 1 ) == 1 )
		randomValue = SwapEndian<T>( randomValue );

	// Add the random value to a random integer in the buffer.
	CAlignmentSafeReference valueInBuffer = ChooseRandomValueReference<T>( pui8Buffer, size );
	valueInBuffer.Set( valueInBuffer.Get() - randomValue );

	return size;
}

//! Replaces a byte in the buffer with a random value.
size_t CAFLMutationFunctions::RandomByteReplace(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size  //!< Size of the buffer.
)
{
	// Check if size is ok.
	if( size <= 0 )
		return MUTATION_FAILED;

	// Choose a random byte and replace it with a random value.
	// Use values from 1 to 255 to avoid using no-op.
	CAlignmentSafeReference asrValue = ChooseRandomValueReference<uint8_t>( pui8Buffer, size );
	asrValue.Set( RandomPosition( 1, std::numeric_limits<uint8_t>::max() ) );

	return size;
}

//! Removes a random sized block from the buffer.
size_t CAFLMutationFunctions::RemoveRandomBlock(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size  //!< Size of the buffer.
)
{
	// This function should not reduce the size to 0.
	// That would be the same as removing the field, which is one of the message level
	// mutation operations done by libprotobuf-mutator.
	if( size <= 1 )
		return MUTATION_FAILED;

	// Choose a random block from the buffer.
	size_t sizeDelete = RandomPosition( 1, ( size - 1 ) );
	size_t sizeRandomBlockIndex = ChooseIndexOfRandomBlock( pui8Buffer, size, sizeDelete );

	
	// Get the number of bytes from the end of the random block to the end of the buffer.
	size_t sizeRemainder = size - sizeRandomBlockIndex - sizeDelete;

	// Move the tail to the position where the block is removed.
	uint8_t* pui8DeleteBlockLocation = pui8Buffer + sizeRandomBlockIndex;
	std::memmove( pui8DeleteBlockLocation, pui8DeleteBlockLocation + sizeDelete, sizeRemainder );

	// Set the tail bytes as zeros.
	// If the mutated field is not variable-sized, this ensures that the value is reduced.
	std::memset( pui8DeleteBlockLocation + sizeRemainder, 0, sizeDelete );

	return size - sizeDelete;
}

//! Inserts a block to the buffer using either a cloned block or repeated random byte.
size_t CAFLMutationFunctions::RandomBlockInsert(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size,  //!< Size of the buffer.
	size_t sizeMax  //!< Maximum size of the mutated buffer.
)
{
	// Check if size is ok.
	if( sizeMax <= size )
		return MUTATION_FAILED;

	// Get the length of the inserted block.
	size_t sizeInsertBlock = RandomPosition( 1, sizeMax - size );

	// Select a random position where the block will be inserted.
	// Copy the bytes after that position to the new end of the buffer.
	// This creates a hole in the buffer that can fit the inserted block.
	size_t sizeInsertPosition = RandomPosition( 0, size );
	size_t sizeTail =  size - sizeInsertPosition;
	size_t sizeNewTailPosition = sizeInsertPosition + sizeInsertBlock;
	std::memcpy( pui8Buffer + sizeNewTailPosition, pui8Buffer + sizeInsertPosition, sizeTail );

	// Clone bytes with 0.75 probability. Otherwise repeat a random byte.
	bool bCloneBytes = RandomPosition( 0, 3 ) != 0;
	if( bCloneBytes && size > 0 )
	{
		// Clone a random block in the buffer.
		size_t sizeCloneFromIndex = ChooseIndexOfRandomBlock( pui8Buffer, sizeMax, sizeInsertBlock );
		std::memmove( pui8Buffer + sizeInsertPosition, pui8Buffer + sizeCloneFromIndex, sizeInsertBlock );
	}
	else
	{
		// Either repeat a random byte from the buffer of a randomly generated byte.
		uint8_t ui8RandomByte;
		bool bRandomRepeatedByte = RandomPosition( 0, 1 ) == 0;
		if( bRandomRepeatedByte || size == 0 )
			ui8RandomByte = RandomPosition( 0, 255 );
		else
			ui8RandomByte = ChooseRandomValueReference<uint8_t>( pui8Buffer, size ).Get();
		std::memset( pui8Buffer + sizeInsertPosition, ui8RandomByte, sizeInsertBlock );
	}

	return size + sizeInsertBlock;
}

//! Overwrites a block in the buffer with either a cloned block or repeated random byte.
size_t CAFLMutationFunctions::RandomChunkOverwrite(
	uint8_t* pui8Buffer,  //!< Buffer that is mutated.
	size_t size  //!< Size of the buffer.
)
{
	// Check if size is ok.
	if( size <= 0 )
		return MUTATION_FAILED;

	// Get the length of the replaced block and a position that can fit the block.
	size_t sizeReplaceBlock = RandomPosition( 1, size );
	size_t sizeReplaceToIndex = ChooseIndexOfRandomBlock( pui8Buffer, size, sizeReplaceBlock );

	// Clone bytes with 0.75 probability. Otherwise repeat a random byte.
	bool bCloneBytes = RandomPosition( 0, 3 ) != 0;
	if( bCloneBytes )
	{
		// Clone a random block in the buffer.
		size_t sizeCloneFromIndex = ChooseIndexOfRandomBlock( pui8Buffer, size, sizeReplaceBlock );
		std::memmove( pui8Buffer + sizeReplaceToIndex, pui8Buffer + sizeCloneFromIndex, sizeReplaceBlock );
	}
	else
	{
		// Either repeat a random byte from the buffer of a randomly generated byte.
		uint8_t ui8RandomByte = RandomPosition( 0, 1 ) ?
				ChooseRandomValueReference<uint8_t>( pui8Buffer, size ).Get() :
				RandomPosition( 0, 255 );
		std::memset( pui8Buffer + sizeReplaceToIndex, ui8RandomByte, sizeReplaceBlock );
	}

	return size;
}

//! Randomly chooses an integer from a range.
size_t CAFLMutationFunctions::RandomPosition(
	size_t sizeMinimumInclusive,  //!< Minimum value in the range.
	size_t sizeMaximumInclusive  //!< Maximum value in the range.
)
{
	// Choose a random integer in the range using the random engine.
	return std::uniform_int_distribution<size_t>( sizeMinimumInclusive, sizeMaximumInclusive )( m_randomengine );
}

//! Chooses a random position in a buffer that can fit a block of specified size.
size_t CAFLMutationFunctions::ChooseIndexOfRandomBlock(
	uint8_t* pui8Buffer,  //!< Buffer to choose from.
	size_t size,  //!< Size of the buffer.
	size_t sizeBlock  //!< Size of the block.
)
{
	assert( size >= sizeBlock );
	return RandomPosition( 0, size - sizeBlock );
}

//! Chooses a random position in a buffer and returns an iteger reference to that position.
template<class T>
CAlignmentSafeReference< T > CAFLMutationFunctions::ChooseRandomValueReference(
	uint8_t* pui8Buffer,  //!< Buffer to choose from.
	size_t size  //!< Size of the buffer.
)
{
	return CAlignmentSafeReference< T >( pui8Buffer + ChooseIndexOfRandomBlock( pui8Buffer, size, sizeof( T ) ) );
}

}  // end namespace
