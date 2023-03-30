/*! \file
Declares the CAlignmentSafeReference class.
*/

#pragma once

#include <cstring>

namespace AFLMutationFunctions
{
	//! Class that enables referencing a value in a buffer even if the buffer is not correctly aligned for the type.
	template < class T >
	class CAlignmentSafeReference
	{
	// Private data.
	private:
		T m_Value;  //!< Copy of the referenced value.
		void* m_pData;  //!< Buffer containing the referenced value.

	// Public interface.
	public:

		//! No default constructor.
		CAlignmentSafeReference() = delete;

		//! No copy constructor.
		CAlignmentSafeReference(
			const CAlignmentSafeReference&
		) = delete;

		//! Move constructor.
		constexpr CAlignmentSafeReference(
			CAlignmentSafeReference&& afrOther
		) :
		m_pData( afrOther.m_pData ),
		m_Value( std::move( afrOther.m_Value ) )
		{}

		//! Constructor.
		/*!
		The buffer pointed to by pData must be at least sizeof( T ) bytes long.
		*/
		explicit CAlignmentSafeReference(
			void* pData  //!< Pointer to the value. Does not need to be aligned for T.
		) :
		m_pData( pData )
		{
			// Use memcpy that is alignment safe to copy the data to a copy value.
			std::memcpy( &m_Value, m_pData, sizeof( T ) );
		}

		//! Gets a copy of the referenced value.
		T Get() const
		{ return m_Value; }

		//! Sets the value in the original buffer.
		/*!
		Behavior is undefined if &other == pData in constructor.
		*/
		void Set(
			const T& value  //!< Value to copy to the original buffer.
		)
		{
			// Update the value copy and set the value in the original buffer.
			m_Value = value;
			std::memcpy( m_pData, &value, sizeof( T ) );
		}
	};
}  // end namespace.