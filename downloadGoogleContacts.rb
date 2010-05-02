#! /usr/bin/ruby

# Copyright (c) 2008 Chad Albers <chad@neomantic.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

###################################################################
# Overview:
# This command line Ruby script downloads the Atom feed of Contacts 
# stored in either a Google account or a Google hosted account.
#
# It uses the ClientLogin Interface described in various locations 
# in Google's API documentation:
# http://code.google.com/apis/contacts/developers_guide_protocol.html#client_login
# http://code.google.com/apis/accounts/docs/AuthForInstalledApps.html
# http://code.google.com/apis/gdata/auth.html
#
# The script downloads a ClientLogin Authentication Token, and stores it in a file
# so that it can be reused later.  Google expires tokens after an undisclosed 
# period of time (i.e., users cannot expire their own tokens!).  When a token
# expires, the script detects this and downloads a new token. (Security warning: 
# the token stored in the file is not encrypted, which means that it can be used
# by used someone else to download your contacts.)
#
# Using the ClientLogin token, the script downloads an Atom feed of the Contacts.
# No further processing occurs. The script simply sends the feed to the standard 
# output, where it can redirected into a file.
#
# The script requires three mandatory options:
# -e or --email EMAIL_ADDRESS             The e-mail address of the Google account,
#                                         including both the username and either
#                                         Google's domain (@gmail.com), or the hosted
#                                       account's domain (@neomantic.com).
# -p or --password PASSWORD               The password of the Google Account.
# -t or --tokenfile FULL_PATH_TO_FILE     The file name and path to the file
#                                         where the script has or will save the
#                                         ClientLogin token.
# -o or --output FULL_PATH_TO_FILE        The file name and path to the file
#                                         where the script has or will save 
#                                         the Atom Feed of the Contacts.
#
# The script accepts one optional option that modifies the output:
# -m --maximum MAXIMUM_NUMBER_OF_CONTACTS  The maximum number of contacts to retrieve.
#                                         (Without supplying this parameter, the number of
#                                          Contacts returned is relatively
#                                          small.)
#
# The script also accepts two more optional options:
# -v or --verbose      Provides messages on the script's progress.
# -h or --help         Provides a message describing these options.
#
# Usage Example:
# To download all your Contacts to a file called "contacts.xml" using a 
# key stored in a file called "token_file", run the following command:
# $> ruby downloadGoogleContacts.rb -e myGoogleAccount@address.com -p sekritpassword -t /home/my_home/token_file -o contacts.xml
#
#
# NOTES
# Script Requirements: 
# The script does not depend on any third-party Ruby code
# outside of Ruby's Core and Standard Libraries.  It was been testing 
# successfully on Ruby 1.8.7 (on Debian GNU/Linux).
#
# Limitations:
# OpenSSL: The script makes no attempt to verify the certificate used to
# encrypt the transmission between sending login information and google's
# website.  Ruby's https class can perform this verification,
# but the script intentionally disables it - using OpenSSL::SSL::VERIFY_NONE.  
# To perform the verification, the script would need to include this certificate.
# from Googles' CA.  This feature can be enable by following the instructions
# posted on this web page:
# http://redcorundum.blogspot.com/2008/03/ssl-certificates-and-nethttps.html
#
# CAPTCHA: The script can handle a number of user, system, and network errors. 
# It can also handle errors noticed by Google. It however cannot handle 
# the case when Google notifies the user that they must re-verify their
# login information by viewing a CAPTCHA image.
#
# Version 0.3
############################################################################

require 'net/http'
require 'net/https'
require 'erb'
require 'optparse'
require 'ostruct'


#Constants, that depend on Google
GOOGLE_LOGIN_URL="https://www.google.com/accounts/ClientLogin"
GOOGLE_CONTACT_FEED_URL = "http://www.google.com/m8/feeds/contacts/"
ACCOUNT_TYPE="HOSTED_OR_GOOGLE"
SERVICE="cp" # contacts service identifier


#Google requires this for ClientLogin, but the value can be changed
SOURCE="neomantic-ruby-1.8.7" #this could be changed

#command line options - global
$options = OpenStruct.new
$options.emailAddress = ""
$options.password = ""
$options.tokenFile = ""
$options.outputFile = ""
$options.maximumResults = 0
$options.verbose = true

# sets up the OptionParser to process the commandline inputs
# the function returns the OptionParser
def setupCommandlineParser

  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$0} [options]"
  
    #Mandatory Options - the program will not work without them
    opts.separator ""
    opts.separator "Mandatory Options:"
    opts.on(:REQUIRED,"-e", "--email EMAIL_ADDRESS", "Google Account E-mail Address") do |emailAddress|
      $options.emailAddress = emailAddress
    end
    opts.on(:REQUIRED, "-p", "--pass PASSWORD", "Password to Google Account") do |password|
      $options.password = password
    end
    opts.on("-t", "--tokenfile FULL_PATH_TO_FILE", "Name and Location of File to Store ClientLogin Token") do |tokenFile|
      $options.tokenFile = tokenFile
    end
    opts.on("-o", "--output FULL_PATH_TO_FILE", "Name and Location of File to Save the Contacts Atom Feed") do |outputFile| 
      $options.outputFile = outputFile      
    end
  
    #Other Options
    opts.separator ""
    opts.separator "Other Options:"
    opts.on("-m", "--maximum MAXIMUM_NUMBER_OF_CONTACTS", "Maximum number of Contacts to download") do |maximumResults|
      $options.maximumResults = maximumResults
    end
    opts.on("-v", "--verbose", "Run verbosely") do |v|
      $options.verbose = v
    end
  # Prints summary of options
    opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit
    end
  end
  
  return parser  
end

# downloads a ClientLogin Authentication token from Google
# the fuction returns the token
def downloadClientLoginToken

  authenticationToken = String.new
  
  url = URI.parse(GOOGLE_LOGIN_URL)
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true if url.scheme == "https"
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
 
  #These must be supplied to google
  data = { "accountType" => ACCOUNT_TYPE, 
      "Email" => ERB::Util.url_encode($options.emailAddress), #encode just in case
      "Passwd" => ERB::Util.url_encode($options.password),  #encode just in case
      "service" => SERVICE, 
      "source" => SOURCE }
  # concatenate the data together with the ampersand separator
  # feeding the data hash into the post request does not perform
  # the concatenate (unknown why)
  form_data = data.map {|key,value| "#{key.to_s}=#{value.to_s}" }.join('&')     

  begin # to catch errors with the posting the query for the token
    puts( "Attempting to download a new ClientLogin Authentication Token...") if $options.verbose
    response = http.post( url.path, form_data )
    #Handles the response, not the exceptions
    case response
      when Net::HTTPSuccess
        puts "Authentification Token Received" if $options.verbose
        # Extract Token for response
        response.body.each { |line|
          if line =~ /Auth=/
            #removes the Auth= portion of the key, and strips the \n
            authenticationToken=line.sub(/Auth=/,'').strip!
          end
        }
      when Net::HTTPForbidden
        # removes the "Error=" part of the response returned by Google 
        # and the linefeed
        handleGoogleError( response.body.sub(/Error=/,'').strip! )
    else
      $stderr.puts( "Google's server returned this error #{response.body.message}" )
    end
  rescue => e
      $stdout.puts( "An exception occurred retrieving your Google's accounts ClientLogin token: #{e.message}")
  end
  
  return authenticationToken
end

# Downloads the Atom feed of the Contacts and pipes the results to the stdout 
def downloadGoogleContacts( clientLoginToken )
 
  #begin building HTTP request
  contactFeedURL = GOOGLE_CONTACT_FEED_URL + ERB::Util.url_encode($options.emailAddress) + "/full"
  # downloading contacts defaults to around 30, so this number can be increased
  contactFeedURL << "?max-results=#{$options.maximumResults}" if $options.maximumResults 
  
  url = URI.parse( contactFeedURL )  
  http = Net::HTTP.new(url.host, url.port)
  # create a Hash containing the header fields
  header = { "Authorization" => "GoogleLogin auth=#{clientLoginToken}"}
  
  # Download the Atom Feed with the Contacts
  # Used url.request_uri (instead of url.path) to include the query "?max-results
  # to the get request
  puts( "Attempting to download your Google Contacts Atom feed..." ) if $options.verbose
  
  begin # for error handling the get request
    response = http.get( url.request_uri, header )
    # Handles the response, not the exceptions
    case response
      when Net::HTTPSuccess
        File.open( $options.outputFile, "w") do |file|
           file.puts( response.body )          
        end
      puts "Your Google Contacts Atom feed was downloaded and saved in #{$options.outputFile}" if $options.verbose
      when Net::HTTPUnauthorized #401
        # error codes specifically related to Authentication tokens
        # http://code.google.com/apis/gdata/auth.html says that only
        # the token disabled and token expire will be returned, but
        # Token Invalid also shows up        
        #      * 401 Token invalid
        #      * 401 Token disabled
        #      * 401 Token expired
        #      * 401 Token revoked
        $stderr.puts( "There was a problem with the Client Login Authentication Token: #{response.message}")
        authenticationToken = downloadClientLoginToken( $options.tokenFile )
        downloadGoogleContacts( authenticationToken )
      when Net::HTTPForbidden #403
        # error codes specifically related with Google accounts
        # From http://code.google.com/apis/gdata/auth.html
        #      * 403 Account disabled
        #      * 403 Account deleted
        $stderr.puts( "There was a problem with the Google account: #{response.message}")
      else
        $stderr.puts( "When downloading your Google Contacts, Google returned this error: #{response.message}" )
    end 
  rescue => e
    $stderr.puts( "An exception occurred retrieving your Google Contacts: #{e.message}" )  
  end
end
 
# Saves the ClientLogin token to the file specified in the command line
# options.  It also replaces old tokens with new ones. 
def saveTokenToFile( tokenFile, newAuthentificationToken )
    
  begin
    #check to see if the file exists, it is greater that 0, and if it is readable
    if File.exists?(tokenFile) and File.size?( tokenFile) and File.readable?( tokenFile )
      File.open( tokenFile, "r+") do |file|
        fileAuthentificationToken = file.readline
        file.rewind
        #if the token is new, write the new token
        file.puts(newAuthentificationToken) unless (fileAuthentificationToken == newAuthentificationToken)
        puts "A new ClientLogin Token has replaced the old one" if $options.verbose
      end
    else
      File.open( tokenFile, "a") do | file |
        file.puts( newAuthentificationToken )
        puts "A new ClientLogin Token has been saved to #{tokenFile}" if $options.verbose
      end
    end
  rescue => e
    $stderr.puts( "An exception occurred saving the ClientLogin Token to its file, #{tokenFile}: #{e.message}")
  end
end

# Delivers to the stderr the Google Error messages when clients fail to
# retrieve the ClientLogin token.
# NOTE - this does not handle redirecting users to the CAPTCHA url
def handleGoogleError( errorString )
  #Error Codes are from http://code.google.com/apis/accounts/docs/AuthForInstalledApps.html
  case errorString
    when 'BadAuthentication'
      $stderr.puts "Google: The login request used a username or password \n that is not recognized."
    when 'NotVerified' 
      $stderr.puts "Google: The account email address has not been verified. \n
        The user will need to access their Google account directly to resolve \n
        the issue before logging in using a non-Google application."
    when 'TermsNotAgreed' 
      $stderr.puts "Google: The user has not agreed to terms. The user \n
      will need to access their Google account directly to resolve the \n
      issue before logging in using a non-Google application."
    when 'CaptchaRequired' 
      $stderr.puts "Google: A CAPTCHA is required."
      #TODO implement CAPTCHA handling
      # It returns a message with this information
      #CaptchaToken=DQAAAGgA...dkI1LK9
      #CaptchaUrl=Captcha?ctoken=HiteT4b0Bk5Xg18_AcVoP6-yFkHPibe7O9EqxeiI7lUSN
    when 'AccountDeleted' 
      $stderr.puts "Google: The user account has been deleted."
    when 'AccountDisabled' 
      $stderr.puts "Google: The user account has been disabled."
    when 'ServiceDisabled' 
      $stderr.puts "Google: The user\'s access to the specified service has \nbeen disabled."
    when 'ServiceUnavailable' 
      $stderr.puts "Google: The service is not available; try again later."
    else #Unknown
      $stderr.puts "Google: The error is unknown or unspecified; the request \ncontained invalid input or was malformed."
  end
end

#Script begins here
begin

  parser = setupCommandlineParser
  parser.parse!(ARGV)

  #Raise exceptions if missing arguments
  if $options.emailAddress.empty?
    raise OptionParser::MissingArgument.new("Missing Google Email Account option: -e or --email")
  end
  if $options.password.empty?
    raise OptionParser::MissingArgument.new("Missing password option: -p or --password")
  end
  if $options.tokenFile.empty?
    raise OptionParser::MissingArgument.new("Missing option identifying ClientLogin Token file: -t or --tokenfile")
  end
  if $options.outputFile.empty?
    raise OptionParser::MissingArgument.new("Missing option identifying output file: -o or --output")
  end
  
  # download the Contacts using the Token key
  if File.exists?( $options.tokenFile ) and File.size?($options.tokenFile) and File.readable?( $options.tokenFile )
      File.open($options.tokenFile, "r+") do |file|
      authenticationToken = file.readline
      if authenticationToken
        puts "UsingClientLogin token stored in #{$options.tokenFile}..." if $options.verbose
      end
      downloadGoogleContacts( authenticationToken )
    end
  else
    # otherwise download the ClientLogin Token
    authenticationToken = downloadClientLoginToken
    saveTokenToFile( $options.tokenFile, authenticationToken )
    downloadGoogleContacts( authenticationToken )
  end

rescue OptionParser::ParseError => error
  $stderr.puts error.message
  $stderr.puts parser #dumps all the options to the stderror
  exit 1
end
