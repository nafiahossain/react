import { useState, useEffect, useRef } from 'react'
//import reactLogo from './assets/react.svg'
//import viteLogo from '/vite.svg'
import './App.css'

function App() {
  const [expandedSearchVisible, setExpandedSearchVisible] = useState(false);
  const [regionFlexVisible, setRegionFlexVisible] = useState(false);
  const [calendarVisible, setCalendarVisible] = useState(false);
  const [guestSelectionVisible, setGuestSelectionVisible] = useState(false);
  const [destination, setDestination] = useState('');
  const [selectedDate, setSelectedDate] = useState(null);
  const [isCheckIn, setIsCheckIn] = useState(true);
  const [currentDate, setCurrentDate] = useState(new Date());
  const [counts, setCounts] = useState({ adults: 0, children: 0, infants: 0, pets: 0 });

  const expandedSearchRef = useRef(null);
  const regionFlexRef = useRef(null);
  const calendarRef = useRef(null);
  const guestSelectionRef = useRef(null);

  const handleNavbarSearchClick = () => {
    setExpandedSearchVisible(!expandedSearchVisible);
  };

  const handleSearchDestinationsClick = () => {
    setRegionFlexVisible(true);
  };

  const handleRegionClick = (text) => {
    setDestination(text);
    setRegionFlexVisible(false);
  };

  const handleCheckInClick = () => {
    setIsCheckIn(true);
    setCalendarVisible(true);
    generateCalendar(currentDate.getFullYear(), currentDate.getMonth());
  };

  const handleCheckOutClick = () => {
    setIsCheckIn(false);
    setCalendarVisible(true);
    generateCalendar(currentDate.getFullYear(), currentDate.getMonth());
  };

  const handleWhoButtonClick = () => {
    setGuestSelectionVisible(!guestSelectionVisible);
  };

  const handleDocumentClick = (event) => {
    if (
      expandedSearchRef.current &&
      !expandedSearchRef.current.contains(event.target) &&
      !document.querySelector('.navbar-search-container').contains(event.target)
    ) {
      setExpandedSearchVisible(false);
    }
    if (
      regionFlexRef.current &&
      !regionFlexRef.current.contains(event.target) &&
      event.target.id !== 'search-destinations-btn'
    ) {
      setRegionFlexVisible(false);
    }
    if (
      calendarRef.current &&
      !calendarRef.current.contains(event.target) &&
      event.target.id !== 'check-in-btn' &&
      event.target.id !== 'check-out-btn'
    ) {
      setCalendarVisible(false);
    }
    if (
      guestSelectionRef.current &&
      !guestSelectionRef.current.contains(event.target) &&
      event.target.id !== 'whoButton'
    ) {
      setGuestSelectionVisible(false);
    }
  };

  useEffect(() => {
    document.addEventListener('click', handleDocumentClick);
    return () => {
      document.removeEventListener('click', handleDocumentClick);
    };
  }, []);

  const generateCalendar = (year, month) => {
    // Generate the calendar here based on the provided year and month
  };

  const updateWhoButton = () => {
    // Update the "Who" button text based on the guest counts
  };

  const updateGuestDescription = () => {
    // Update the guest description paragraph based on the guest counts
  };

  const updateDisplay = (type) => {
    // Update the display for the specific type of guest
  };

  const handleDateSelect = (date) => {
    setSelectedDate(date);
    const buttonToUpdate = isCheckIn ? 'check-in-btn' : 'check-out-btn';
    document.getElementById(buttonToUpdate).innerHTML = `${isCheckIn ? '<strong>Check in</strong>' : '<strong>Check out</strong>'}<br>${date.toLocaleDateString()}`;
    updateCalendarSelection();
    setIsCheckIn(!isCheckIn);
  };

  const updateCalendarSelection = () => {
    // Update the calendar selection display based on the selected date
  };

  return (
    <div>
      <nav className="navbar">
        <div className="navbar-search-container">
          <button id="anywhere-btn-id" className="anywhere-btn-class" onClick={handleNavbarSearchClick}>Anywhere</button>
          <p>|</p>
          <button id="anyweek-btn-id" className="anywhere-btn-class" onClick={handleNavbarSearchClick}>Any week</button>
          <p>|</p>
          <input type="text" className="search-input" placeholder="Add guests" onClick={handleNavbarSearchClick} />
          <button className="search-button" id="guest-search-button" onClick={handleNavbarSearchClick}>
            <img src="images/search.png" alt="Search" width="15" />
          </button>
        </div>
        <div className="menu-icons">
          <div className="menu-icon">🌐</div>
          <div className="menu-icon">☰</div>
          <div className="menu-icon">👤</div>
        </div>
      </nav>

      <div className="expanded-container">
        <div className="expanded-search" id="expanded-search" style={{ display: expandedSearchVisible ? 'block' : 'none' }} ref={expandedSearchRef}>
          <div className="search-options">
            <button id="search-destinations-btn" onClick={handleSearchDestinationsClick}><strong>Where</strong><br />{destination ? destination : 'Search destinations'}</button>
            <p>|</p>
            <button id="check-in-btn" onClick={handleCheckInClick}><strong>Check in</strong><br />Add dates</button>
            <p>|</p>
            <button id="check-out-btn" onClick={handleCheckOutClick}><strong>Check out</strong><br />Add dates</button>
            <p>|</p>
            <button id="whoButton" onClick={handleWhoButtonClick}><strong>Who</strong><br />Add guests</button>
            <button id="search-btn">Search</button>
          </div>
        </div>

        <div className="region-flex" id="region-flex" style={{ display: regionFlexVisible ? 'block' : 'none' }} ref={regionFlexRef}>
          <h3>Search by region</h3>
          <div className="region-items">
            {['Flexible', 'Southeast Asia', 'Canada', 'Europe', 'Thailand', 'Middle East'].map((region, index) => (
              <div className="region-item" key={index} onClick={() => handleRegionClick(region)}>
                <img src={`images/map${index + 1}.png`} alt={region} />
                <p>{region}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="calendar" id="calendar" style={{ display: calendarVisible ? 'block' : 'none' }} ref={calendarRef}>
          <div className="calendar-header">
            <button id="prev-month" onClick={() => setCurrentDate(new Date(currentDate.setMonth(currentDate.getMonth() - 1)))}>&lt;</button>
            <span id="current-month-year"></span>
            <button id="next-month" onClick={() => setCurrentDate(new Date(currentDate.setMonth(currentDate.getMonth() + 1)))}>&gt;</button>
          </div>
          <div className="calendar-body" id="calendar-body"></div>
          <div className="date-range-options">
            {[0, 1, 2, 3, 7].map(days => (
              <button className="date-range-btn" data-days={days} key={days} onClick={() => updateCalendarSelection(days)}>
                {days === 0 ? 'Exact dates' : `± ${days} day${days > 1 ? 's' : ''}`}
              </button>
            ))}
          </div>
        </div>

        <div id="guestSelection" className="guest-selection" style={{ display: guestSelectionVisible ? 'block' : 'none' }} ref={guestSelectionRef}>
          {['Adults', 'Children', 'Infants', 'Pets'].map((guest, index) => (
            <div className="guest-type" key={index}>
              <div className="guest-info">
                <h3>{guest}</h3>
                <p>{guest === 'Adults' ? 'Ages 13 or above' : guest === 'Children' ? 'Ages 2 - 12' : guest === 'Infants' ? 'Under 2' : 'Bringing a service animal?'}</p>
              </div>
              <div className="guest-controls">
                <button className="minus" data-type={guest.toLowerCase()} onClick={() => setCounts({ ...counts, [guest.toLowerCase()]: Math.max(counts[guest.toLowerCase()] - 1, 0) })}>-</button>
                <span className="count" data-type={guest.toLowerCase()}>{counts[guest.toLowerCase()]}</span>
                <button className="plus" data-type={guest.toLowerCase()} onClick={() => setCounts({ ...counts, [guest.toLowerCase()]: counts[guest.toLowerCase()] + 1 })}>+</button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default App;

/*
import React, { useState, useRef, useEffect } from 'react';
import './styles.css'; // Adjust the path according to your project structure

function App() {
  const [expandedSearchVisible, setExpandedSearchVisible] = useState(false);
  const [calendarVisible, setCalendarVisible] = useState(false);
  const [isCheckIn, setIsCheckIn] = useState(true);
  const expandedSearchRef = useRef(null);
  const calendarRef = useRef(null);

  const handleNavbarSearchClick = () => {
    setExpandedSearchVisible(!expandedSearchVisible);
    setCalendarVisible(false); // Hide calendar when toggling expanded search
  };

  const handleCheckInClick = () => {
    setIsCheckIn(true);
    setCalendarVisible(true);
  };

  const handleCheckOutClick = () => {
    setIsCheckIn(false);
    setCalendarVisible(true);
  };

  const handleDocumentClick = (event) => {
    if (
      expandedSearchRef.current &&
      !expandedSearchRef.current.contains(event.target) &&
      !document.querySelector('.navbar-search-container').contains(event.target)
    ) {
      setExpandedSearchVisible(false);
    }
    if (
      calendarRef.current &&
      !calendarRef.current.contains(event.target) &&
      event.target.id !== 'check-in-btn' &&
      event.target.id !== 'check-out-btn'
    ) {
      setCalendarVisible(false);
    }
  };

  useEffect(() => {
    document.addEventListener('click', handleDocumentClick);
    return () => {
      document.removeEventListener('click', handleDocumentClick);
    };
  }, []);

  
*/
