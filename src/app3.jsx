import React, { useState, useEffect } from 'react';
import { Search, Globe, Menu, User, ChevronLeft, ChevronRight } from 'lucide-react';

import './App.css'

const BookingApp = () => {
  const [isExpandedSearchVisible, setIsExpandedSearchVisible] = useState(false);
  const [isRegionGridVisible, setIsRegionGridVisible] = useState(false);
  const [selectedRegion, setSelectedRegion] = useState('Search destinations');
  const [isCalendarVisible, setIsCalendarVisible] = useState(false);
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState(null);
  const [selectedDateRange, setSelectedDateRange] = useState(0);
  const [isCheckIn, setIsCheckIn] = useState(true);
  const [isGuestSelectionVisible, setIsGuestSelectionVisible] = useState(false);
  const [guestCounts, setGuestCounts] = useState({ adults: 0, children: 0, infants: 0, pets: 0 });

  const toggleExpandedSearch = () => {
    setIsExpandedSearchVisible(!isExpandedSearchVisible);
  };

  const toggleRegionGrid = () => {
    setIsRegionGridVisible(!isRegionGridVisible);
  };

  const selectRegion = (region) => {
    setSelectedRegion(region);
    setIsRegionGridVisible(false);
  };

  const generateCalendar = (year, month) => {
    const firstDay = new Date(year, month, 1).getDay();
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const today = new Date();
    const calendarDays = [];

    for (let i = 0; i < firstDay; i++) {
      calendarDays.push(<div key={`empty-${i}`} />);
    }

    for (let day = 1; day <= daysInMonth; day++) {
      const date = new Date(year, month, day);
      const isDisabled = date < today.setHours(0, 0, 0, 0);
      const isSelected = selectedDate && day === selectedDate.getDate() && month === selectedDate.getMonth() && year === selectedDate.getFullYear();

      calendarDays.push(
        <div
          key={`day-${day}`}
          className={`calendar-day ${isDisabled ? 'disabled' : ''} ${isSelected ? 'selected' : ''}`}
          onClick={() => !isDisabled && selectDate(date)}
        >
          {day}
        </div>
      );
    }

    return calendarDays;
  };

  const selectDate = (date) => {
    setSelectedDate(date);
    setIsCheckIn(!isCheckIn);
  };

  const updateGuestCount = (type, increment) => {
    setGuestCounts(prevCounts => ({
      ...prevCounts,
      [type]: Math.max(0, prevCounts[type] + increment)
    }));
  };

  const getGuestDescription = () => {
    const descriptions = {
      adults: 'adult',
      children: 'child',
      infants: 'infant',
      pets: 'pet'
    };
    
    return Object.entries(guestCounts)
      .filter(([_, count]) => count > 0)
      .map(([type, count]) => `${count} ${descriptions[type]}${count > 1 ? 's' : ''}`)
      .join(', ') || 'Add guests';
  };

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (!event.target.closest('.expanded-container') && !event.target.closest('.navbar-search-container')) {
        setIsExpandedSearchVisible(false);
        setIsRegionGridVisible(false);
        setIsCalendarVisible(false);
        setIsGuestSelectionVisible(false);
      }
    };

    document.addEventListener('click', handleOutsideClick);
    return () => document.removeEventListener('click', handleOutsideClick);
  }, []);

  return (
    <div className="booking-app">
      <nav className="navbar">
        <div className="navbar-search-container">
          <button onClick={toggleExpandedSearch} className="anywhere-btn-class">Anywhere</button>
          <p>|</p>
          <button onClick={toggleExpandedSearch} className="anywhere-btn-class">Any week</button>
          <p>|</p>
          <input type="text" className="search-input" placeholder="Add guests" onClick={toggleExpandedSearch} />
          <button className="search-button" onClick={toggleExpandedSearch}>
            <Search size={15} />
          </button>
        </div>
        <div className="menu-icons">
          <Globe className="menu-icon" />
          <Menu className="menu-icon" />
          <User className="menu-icon" />
        </div>
      </nav>
      
      {isExpandedSearchVisible && (
        <div className="expanded-container">
          <div className="expanded-search">
            <div className="search-options">
              <button onClick={toggleRegionGrid}>
                <strong>Where</strong><br />{selectedRegion}
              </button>
              <p>|</p>
              <button onClick={() => { setIsCheckIn(true); setIsCalendarVisible(true); }}>
                <strong>Check in</strong><br />
                {selectedDate && isCheckIn ? selectedDate.toLocaleDateString() : 'Add dates'}
              </button>
              <p>|</p>
              <button onClick={() => { setIsCheckIn(false); setIsCalendarVisible(true); }}>
                <strong>Check out</strong><br />
                {selectedDate && !isCheckIn ? selectedDate.toLocaleDateString() : 'Add dates'}
              </button>
              <p>|</p>
              <button onClick={() => setIsGuestSelectionVisible(!isGuestSelectionVisible)}>
                <strong>Who</strong><br />{getGuestDescription()}
              </button>
              <button id="search-btn">Search</button>
            </div>
          </div>

          {isRegionGridVisible && (
            <div className="region-flex">
              <h3>Search by region</h3>
              <div className="region-items">
                {['I\'m flexible', 'Southeast Asia', 'Canada', 'Europe', 'Thailand', 'Middle East'].map((region, index) => (
                  <div key={index} className="region-item" onClick={() => selectRegion(region)}>
                    <img src={`images/map${index + 1}.png`} alt={region} />
                    <p>{region}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {isCalendarVisible && (
            <div className="calendar">
              <div className="calendar-header">
                <button onClick={() => setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() - 1, 1))}>
                  <ChevronLeft />
                </button>
                <span>{currentDate.toLocaleString('default', { month: 'long', year: 'numeric' })}</span>
                <button onClick={() => setCurrentDate(new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 1))}>
                  <ChevronRight />
                </button>
              </div>
              <div className="calendar-body">
                {generateCalendar(currentDate.getFullYear(), currentDate.getMonth())}
              </div>
              <div className="date-range-options">
                {[0, 1, 2, 3, 7].map((days) => (
                  <button
                    key={days}
                    className={`date-range-btn ${selectedDateRange === days ? 'selected' : ''}`}
                    onClick={() => setSelectedDateRange(days)}
                  >
                    {days === 0 ? 'Exact dates' : `± ${days} day${days > 1 ? 's' : ''}`}
                  </button>
                ))}
              </div>
            </div>
          )}

          {isGuestSelectionVisible && (
            <div className="guest-selection">
              {['adults', 'children', 'infants', 'pets'].map((type) => (
                <div key={type} className="guest-type">
                  <div className="guest-info">
                    <h3>{type.charAt(0).toUpperCase() + type.slice(1)}</h3>
                    <p>{type === 'adults' ? 'Ages 13 or above' : type === 'children' ? 'Ages 2 - 12' : type === 'infants' ? 'Under 2' : 'Bringing a service animal?'}</p>
                  </div>
                  <div className="guest-controls">
                    <button onClick={() => updateGuestCount(type, -1)} disabled={guestCounts[type] === 0}>-</button>
                    <span>{guestCounts[type]}</span>
                    <button onClick={() => updateGuestCount(type, 1)}>+</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default BookingApp;