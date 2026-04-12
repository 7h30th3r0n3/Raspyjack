# AI Integration for Ragnar

This document describes the AI integration feature added to Ragnar, which provides intelligent network analysis and vulnerability summaries using OpenAI's GPT-5 Nano.

## Overview

The AI integration brings PWNAGOTCHI-style intelligence to Ragnar, providing:
- Network security summaries
- Vulnerability analysis and prioritization
- Network weakness identification
- Attack vector analysis

## Features

### 1. Network Security Summaries
AI analyzes your network scan data and provides concise summaries of the overall security posture, highlighting key findings and actionable recommendations.

### 2. Vulnerability Assessment
Intelligent analysis of discovered vulnerabilities with:
- Priority recommendations for remediation
- Risk assessment
- Critical vulnerability highlights

### 3. Network Weakness Identification
Identifies potential attack vectors and security gaps in your network:
- Weak configurations
- Exposed services
- Potential exploitation paths

## Configuration

### 1. Enable AI in Config Tab

1. Navigate to the **Config** tab in the web interface
2. Scroll to the **AI Integration (GPT-5 Nano)** section
3. Configure the following settings:

- **ai_enabled**: Set to `true` to enable AI features
- **openai_api_token**: Your OpenAI API token (required)
- **ai_model**: Model to use (default: "gpt-5-nano")
- **ai_analysis_enabled**: Enable/disable AI analysis
- **ai_vulnerability_summaries**: Enable vulnerability summaries
- **ai_network_insights**: Enable network insights
- **ai_max_tokens**: Maximum tokens per response (default: 500)
- **ai_temperature**: Creativity setting (default: 0.7)

### 2. Get an OpenAI API Token

1. Visit [OpenAI Platform](https://platform.openai.com/)
2. Sign up or log in to your account
3. Navigate to API Keys section
4. Create a new API key
5. Copy the API key and paste it into the `openai_api_token` field in Ragnar

### 3. Save Configuration

Click "Save Configuration" to apply the settings. The AI service will initialize automatically.

## Usage

### Dashboard View

Once configured, AI insights appear automatically on the Dashboard tab:

1. **Network Security Summary** - Overall security posture analysis
2. **Vulnerability Assessment** - Prioritized vulnerability analysis
3. **Network Weaknesses** - Identified attack vectors and security gaps

### Refresh Insights

Click the "Refresh" button in the AI Insights section to:
- Clear the cache
- Generate new analysis with latest data
- Get updated recommendations

## API Endpoints

The following API endpoints are available for programmatic access:

### GET /api/ai/status
Returns AI service status and configuration
```json
{
  "enabled": true,
  "available": true,
  "model": "gpt-5-nano",
  "capabilities": {
    "network_insights": true,
    "vulnerability_summaries": true
  },
  "configured": true
}
```

### GET /api/ai/insights
Returns comprehensive AI insights
```json
{
  "enabled": true,
  "timestamp": "2025-11-20T20:39:19.888Z",
  "network_summary": "Your network shows 10 active targets...",
  "vulnerability_analysis": "Critical vulnerabilities detected...",
  "weakness_analysis": "Potential attack vectors identified..."
}
```

### GET /api/ai/network-summary
Returns network security summary only

### GET /api/ai/vulnerabilities
Returns vulnerability analysis only

### GET /api/ai/weaknesses
Returns weakness analysis only

### POST /api/ai/clear-cache
Clears the AI response cache

## Technical Details

### Architecture

The AI integration consists of:

1. **ai_service.py** - Core AI service module
   - OpenAI API integration
   - Response caching (5-minute TTL)
   - Network analysis logic
   
2. **API Endpoints** (webapp_modern.py)
   - RESTful endpoints for AI functionality
   - Integration with network intelligence
   
3. **Web UI** (index_modern.html, ragnar_modern.js)
   - Dashboard display components
   - Auto-loading and refresh functionality

### Caching Strategy

AI responses are cached for 5 minutes to:
- Reduce API costs
- Improve response times
- Prevent redundant analysis

Cache is automatically cleared on:
- Manual refresh
- Configuration changes
- Network changes

### Integration with Network Intelligence

The AI service integrates seamlessly with Ragnar's Network Intelligence system:
- Uses active findings for current network
- Analyzes vulnerabilities and credentials
- Respects network context and history

## Personality

The AI assistant ("Ragnar") is designed to be:
- **Knowledgeable**: Expert in cybersecurity and penetration testing
- **Witty**: Occasionally includes personality in responses
- **Concise**: Provides actionable insights without verbosity
- **Tactical**: Focuses on practical recommendations

Similar to PWNAGOTCHI, Ragnar provides intelligent analysis that helps both attackers (in authorized pentests) and defenders understand network security.

## Cost Considerations

### API Usage

The OpenAI API is pay-per-use. To minimize costs:

1. **Caching**: Responses cached for 5 minutes
2. **Token Limits**: Configurable max_tokens (default: 500)
3. **Manual Refresh**: Insights only regenerated on demand
4. **Smart Analysis**: Only analyzes when data changes

### Estimated Costs

With default settings (500 tokens max):
- Network summary: ~0.5-1 cent per request
- Vulnerability analysis: ~0.5-1 cent per request
- Total per refresh: ~1.5-3 cents

Costs vary based on:
- Chosen model
- Token limits
- Refresh frequency
- Network size

## Troubleshooting

### AI Insights Not Appearing

1. Check that `ai_enabled` is set to `true`
2. Verify `openai_api_token` is configured
3. Check browser console for errors
4. Verify internet connectivity

### "AI service not enabled" Message

1. Ensure OpenAI package is installed: `pip install openai`
2. Check API token is valid
3. Verify configuration was saved

### Empty or Generic Responses

1. Run network scans to gather data
2. Wait for vulnerability scans to complete
3. Ensure network intelligence is enabled
4. Check that data is flowing to the AI service

### API Errors

1. Verify API token is valid
2. Check OpenAI account has credits
3. Ensure model name is correct
4. Review API rate limits

## Security Considerations

### API Token Security

⚠️ **IMPORTANT**: Protect your OpenAI API token

- Store in configuration file (not in code)
- Use environment variables in production
- Rotate tokens periodically
- Monitor API usage for anomalies

### Data Privacy

AI analysis sends the following data to OpenAI:
- Network statistics (counts)
- Vulnerability summaries (anonymized)
- Service information
- Host identifiers (IPs)

**Never send**:
- Actual credentials
- Sensitive file contents
- Personal data
- Proprietary information

### Compliance

Consider regulatory requirements when using AI:
- GDPR (if processing EU data)
- HIPAA (if analyzing healthcare networks)
- PCI-DSS (if scanning payment networks)

Ensure AI usage complies with your organization's policies.

## Future Enhancements

Planned improvements:
- [ ] Credential analysis with security recommendations
- [ ] Attack path recommendations
- [ ] Automated remediation suggestions
- [ ] Integration with threat intelligence feeds
- [ ] Custom AI prompts and personalities
- [ ] Local LLM support (privacy-focused option)
- [ ] Multi-model support

## Support

For issues or questions:
1. Check the [GitHub Issues](https://github.com/PierreGode/Ragnar/issues)
2. Review the main [README](README.md)
3. Submit a bug report with:
   - AI configuration (redact API token)
   - Error messages
   - Browser console logs
   - Steps to reproduce

## License

This AI integration is part of Ragnar and follows the same license as the main project.
