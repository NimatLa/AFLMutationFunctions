/*! \file
Declares the CVectorConcatenation class.
*/

#pragma once

#include <vector>
#include <stdexcept>

namespace AFLMutationFunctions
{
//!
/*!
The behavior is undefined if the vectors are modified after concatenating.
*/
template< class T >
class CVectorConcatenation
{

// Public type definitions.
public:
	using value_type = T;
	using size_type = typename std::vector< T >::size_type;
	using reference = typename std::vector< T >::reference;
	using const_reference = typename std::vector< T >::const_reference;

// Public interface.
public:
	//! Default constructor.
	CVectorConcatenation() = default;

	//! Copy constructor.
	CVectorConcatenation(
		const CVectorConcatenation& vcOther  //!< Vector concatenation to copy.
	) = default;

	//! Move constructor.
	CVectorConcatenation(
		CVectorConcatenation&& vcOther //!< Vector concatenation to copy.
	) = default;

	//! Adds a vector to the end of the concatenation.
	/*!
	The vector passed in pvecSource must outlive this vector concatenation.
	*/
	void Concatenate(
		std::vector< T >* pvecSource  //!< Vector to add to the concatenation.
	)
	{
		// Add the vector pointer to the collection.
		m_vecpvecConcatenated.push_back( pvecSource );
		m_sizeElements += pvecSource->size();
	}

	//! Returns a reference to the element at specified index.
	reference operator[](
		size_type sizePosition  //! Index of the element to get.
	)
	{ return At( sizePosition ); }

	//! Returns a constant reference to the element at specified index.
	const_reference operator[](
		size_type sizePosition  //! Index of the element to get.
	) const
	{ return At( sizePosition ); }

	//! Returns the number of elements in all the concatenated vectors.
	constexpr size_type Size() const noexcept
	{ return m_sizeElements; }

	//! Clears the contents.
	/*!
	The content of the concatenated vectors are not cleared.
	*/
	constexpr void Clear() noexcept
	{
		// Clear the internal vector.
		m_vecpvecConcatenated.clear();
		m_sizeElements = 0;
	}


// Private interface.
private:
	//! Returns a reference to the element at specified index.
	reference At(
		size_type sizePosition  //! Index of the element to get.
	) const
	{
		// Find which vector the element belongs to.
		for( std::vector< T >* pvecNext : m_vecpvecConcatenated )
		{
			// Return the element from the vector if the position is within range.
			if( sizePosition < pvecNext->size() )
				return pvecNext->at( sizePosition );
			else
				sizePosition -= pvecNext->size();
		}

		// The element was not in range of any of the vector.
		throw std::out_of_range( "Position is out of range." );
	}

// Private data.
private:
	std::vector< std::vector< T >* > m_vecpvecConcatenated;
	size_type m_sizeElements = 0;
};  // end class
}  // end namespace