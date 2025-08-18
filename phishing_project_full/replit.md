# Gmail Phishing Detector

## Overview

This is a Streamlit-based web application that provides real-time phishing detection for Gmail inboxes. The system analyzes incoming emails using multiple detection mechanisms including content analysis, URL scanning, sender verification, and machine learning-based risk scoring to identify potential phishing attempts.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

The application follows a modular architecture with clear separation of concerns:

### Frontend Architecture
- **Streamlit Web Interface**: Single-page application with sidebar controls for configuration
- **Real-time Dashboard**: Displays email analysis results, risk scores, and threat indicators
- **Interactive Components**: Authentication flow, email filtering, and detailed analysis views

### Backend Architecture
- **Modular Processing Pipeline**: Composed of specialized components for different analysis types
- **Gmail Integration**: OAuth2-based authentication and email fetching through Gmail API
- **Machine Learning Engine**: Risk scoring using trained models for phishing detection
- **URL Analysis Engine**: Dedicated component for analyzing suspicious links and domains

## Key Components

### 1. Gmail Client (`gmail_client.py`)
- **Purpose**: Handles Gmail API authentication and email retrieval
- **Authentication**: OAuth2 flow with client credentials
- **Functionality**: Fetches recent emails with configurable limits
- **Current State**: Simulated implementation for demonstration (requires actual Gmail API integration)

### 2. Phishing Detector (`phishing_detector.py`)
- **Purpose**: Core ML-based phishing detection engine
- **Features**: 
  - Keyword-based threat detection
  - Domain reputation analysis
  - Risk scoring algorithm
  - Pre-trained model integration
- **Dependencies**: NLTK for text processing, scikit-learn for ML models

### 3. Email Processor (`email_processor.py`)
- **Purpose**: Orchestrates the complete email analysis pipeline
- **Functions**:
  - Processes emails through all detection mechanisms
  - Combines risk scores from multiple sources
  - Generates comprehensive threat summaries
  - Analyzes sender, content, and subject characteristics

### 4. URL Analyzer (`url_analyzer.py`)
- **Purpose**: Specialized URL and domain analysis
- **Capabilities**:
  - Extracts URLs from email content
  - Analyzes domain reputation and age
  - Detects suspicious TLDs and phishing keywords
  - DNS and network-based verification

### 5. Utilities (`utils.py`)
- **Purpose**: Common helper functions for email processing
- **Functions**: Content cleaning, email parsing, domain extraction

## Data Flow

1. **Authentication**: User authenticates with Gmail through OAuth2 flow
2. **Email Retrieval**: System fetches recent emails from Gmail API
3. **Processing Pipeline**: Each email goes through:
   - Content extraction and cleaning
   - Phishing detection analysis
   - URL scanning and reputation checking
   - Sender verification
   - Risk score calculation
4. **Results Aggregation**: All analysis results are combined into comprehensive reports
5. **UI Presentation**: Results displayed in real-time dashboard with filtering and sorting

## External Dependencies

### Core Libraries
- **Streamlit**: Web application framework
- **pandas**: Data manipulation and analysis
- **scikit-learn**: Machine learning models and text processing
- **NLTK**: Natural language processing for content analysis
- **requests**: HTTP client for URL verification
- **dnspython**: DNS resolution for domain analysis

### Gmail Integration
- **Gmail API**: Email retrieval and authentication
- **OAuth2**: Secure authentication flow
- **Environment Variables**: Client credentials and configuration

### Machine Learning
- **TF-IDF Vectorization**: Text feature extraction
- **Random Forest**: Classification model for phishing detection
- **Pre-trained Models**: Pickle-serialized models for deployment

## Deployment Strategy

### Environment Setup
- **Credentials**: Gmail API credentials stored as environment variables
- **Dependencies**: All Python packages specified in requirements
- **NLTK Data**: Automatic download of required language models

### Configuration
- **Client ID/Secret**: Gmail API credentials
- **Redirect URI**: OAuth2 callback configuration
- **Model Files**: Pre-trained ML models for phishing detection

### Security Considerations
- **OAuth2 Flow**: Secure Gmail authentication
- **Token Management**: Access token storage and refresh
- **Credential Protection**: Environment-based secret management

### Scalability Notes
- **Session State**: Streamlit session management for user data
- **Caching**: Potential for email and analysis result caching
- **Rate Limiting**: Gmail API rate limit considerations
- **Model Updates**: Framework for updating ML models

## Development Notes

The current implementation includes simulated Gmail API responses for demonstration purposes. For production deployment:

1. **Gmail API Integration**: Implement actual OAuth2 flow and API calls
2. **Model Training**: Train phishing detection models on real email datasets
3. **Database Integration**: Consider adding persistent storage for analysis history
4. **Performance Optimization**: Implement caching and batch processing for large email volumes
5. **Security Hardening**: Add comprehensive input validation and secure credential management