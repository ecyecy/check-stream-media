#!/bin/bash
shopt -s expand_aliases
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_SkyBlue="\033[36m"
Font_White="\033[37m"
Font_Suffix="\033[0m"

while getopts ":I:M:EX:P:" optname; do
    case "$optname" in
    "I")
        iface="$OPTARG"
        useNIC="--interface $iface"
        ;;
    "M")
        if [[ "$OPTARG" == "4" ]]; then
            NetworkType=4
        elif [[ "$OPTARG" == "6" ]]; then
            NetworkType=6
        fi
        ;;
    "E")
        language="e"
        ;;
    "X")
        XIP="$OPTARG"
        xForward="--header X-Forwarded-For:$XIP"
        ;;
    "P")
        proxy="$OPTARG"
        usePROXY="-x $proxy"
        ;;
    ":")
        echo "Unknown error while processing options"
        exit 1
        ;;
    esac

done

if [ -z "$iface" ]; then
    useNIC=""
fi

if [ -z "$XIP" ]; then
    xForward=""
fi

if [ -z "$proxy" ]; then
    usePROXY=""
elif [ -n "$proxy" ]; then
    NetworkType=4
fi

if ! mktemp -u --suffix=RRC &>/dev/null; then
    is_busybox=1
fi

UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
UA_Dalvik="Dalvik/2.1.0 (Linux; U; Android 9; ALP-AL00 Build/HUAWEIALP-AL00)"
Media_Cookie=$(curl -s --retry 3 --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies")
IATACode=$(curl -s --retry 3 --max-time 10 "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/reference/IATACode.txt")
WOWOW_Cookie=$(echo "$Media_Cookie" | awk 'NR==3')
TVer_Cookie="Accept: application/json;pk=BCpkADawqM0_rzsjsYbC1k1wlJLU4HiAtfzjxdUmfvvLUQB-Ax6VA-p-9wOEZbCEm3u95qq2Y1CQQW1K9tPaMma9iAqUqhpISCmyXrgnlpx9soEmoVNuQpiyGsTpePGumWxSs1YoKziYB6Wz"

blue()
{
    echo -e "\033[34m[input]\033[0m"
}

countRunTimes() {
    if [ "$is_busybox" == 1 ]; then
        count_file=$(mktemp)
    else
        count_file=$(mktemp --suffix=RRC)
    fi
    RunTimes=$(curl -s --max-time 10 "https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fcheck.unclock.media&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=visit&edge_flat=false" >"${count_file}")
    TodayRunTimes=$(cat "${count_file}" | tail -3 | head -n 1 | awk '{print $5}')
    TotalRunTimes=$(($(cat "${count_file}" | tail -3 | head -n 1 | awk '{print $7}') + 2527395))
}
countRunTimes

checkOS() {
    ifTermux=$(echo $PWD | grep termux)
    ifMacOS=$(uname -a | grep Darwin)
    if [ -n "$ifTermux" ]; then
        os_version=Termux
        is_termux=1
    elif [ -n "$ifMacOS" ]; then
        os_version=MacOS
        is_macos=1
    else
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    fi

    if [[ "$os_version" == "2004" ]] || [[ "$os_version" == "10" ]] || [[ "$os_version" == "11" ]]; then
        is_windows=1
        ssll="-k --ciphers DEFAULT@SECLEVEL=1"
    fi

    if [ "$(which apt 2>/dev/null)" ]; then
        InstallMethod="apt"
        is_debian=1
    elif [ "$(which dnf 2>/dev/null)" ] || [ "$(which yum 2>/dev/null)" ]; then
        InstallMethod="yum"
        is_redhat=1
    elif [[ "$os_version" == "Termux" ]]; then
        InstallMethod="pkg"
    elif [[ "$os_version" == "MacOS" ]]; then
        InstallMethod="brew"
    fi
}

checkCPU() {
    CPUArch=$(uname -m)
    if [[ "$CPUArch" == "aarch64" ]]; then
        arch=_arm64
    elif [[ "$CPUArch" == "i686" ]]; then
        arch=_i686
    elif [[ "$CPUArch" == "arm" ]]; then
        arch=_arm
    elif [[ "$CPUArch" == "x86_64" ]] && [ -n "$ifMacOS" ]; then
        arch=_darwin
    fi
}

checkDependencies() {

    # os_detail=$(cat /etc/os-release 2> /dev/null)

    if ! command -v python &>/dev/null; then
        if command -v python3 &>/dev/null; then
            alias python="python3"
        else
            if [ "$is_debian" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                $InstallMethod update >/dev/null 2>&1
                $InstallMethod install python -y >/dev/null 2>&1
            elif [ "$is_redhat" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                if [[ "$os_version" -gt 7 ]]; then
                    $InstallMethod makecache >/dev/null 2>&1
                    $InstallMethod install python3 -y >/dev/null 2>&1
                    alias python="python3"
                else
                    $InstallMethod makecache >/dev/null 2>&1
                    $InstallMethod install python -y >/dev/null 2>&1
                fi

            elif [ "$is_termux" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                $InstallMethod update -y >/dev/null 2>&1
                $InstallMethod install python -y >/dev/null 2>&1

            elif [ "$is_macos" == 1 ]; then
                echo -e "${Font_Green}Installing python${Font_Suffix}"
                $InstallMethod install python
            fi
        fi
    fi

    if ! command -v dig &>/dev/null; then
        if [ "$is_debian" == 1 ]; then
            echo -e "${Font_Green}Installing dnsutils${Font_Suffix}"
            $InstallMethod update >/dev/null 2>&1
            $InstallMethod install dnsutils -y >/dev/null 2>&1
        elif [ "$is_redhat" == 1 ]; then
            echo -e "${Font_Green}Installing bind-utils${Font_Suffix}"
            $InstallMethod makecache >/dev/null 2>&1
            $InstallMethod install bind-utils -y >/dev/null 2>&1
        elif [ "$is_termux" == 1 ]; then
            echo -e "${Font_Green}Installing dnsutils${Font_Suffix}"
            $InstallMethod update -y >/dev/null 2>&1
            $InstallMethod install dnsutils -y >/dev/null 2>&1
        elif [ "$is_macos" == 1 ]; then
            echo -e "${Font_Green}Installing bind${Font_Suffix}"
            $InstallMethod install bind
        fi
    fi

    if [ "$is_macos" == 1 ]; then
        if ! command -v md5sum &>/dev/null; then
            echo -e "${Font_Green}Installing md5sha1sum${Font_Suffix}"
            $InstallMethod install md5sha1sum
        fi
    fi

}
checkDependencies

local_ipv4=$(curl $useNIC $usePROXY -4 -s --max-time 10 api64.ipify.org)
local_ipv4_asterisk=$(awk -F"." '{print $1"."$2".*.*"}' <<<"${local_ipv4}")
local_ipv6=$(curl $useNIC -6 -s --max-time 20 api64.ipify.org)
local_ipv6_asterisk=$(awk -F":" '{print $1":"$2":"$3":*:*"}' <<<"${local_ipv6}")
local_isp4=$(curl $useNIC -s -4 --max-time 10 --user-agent "${UA_Browser}" "https://api.ip.sb/geoip/${local_ipv4}" | grep organization | cut -f4 -d '"')
local_isp6=$(curl $useNIC -s -6 --max-time 10 --user-agent "${UA_Browser}" "https://api.ip.sb/geoip/${local_ipv6}" | grep organization | cut -f4 -d '"')

ShowRegion() {
    echo -e "${Font_Yellow} ---${1}---${Font_Suffix}"
}

###########################################
#                                         #
#           required check item           #
#                                         #
###########################################

# Netflix
MediaUnlockTest_Netflix() {
    # LEGO Ninjago
    local result1=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/81280792' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")
    # Breaking bad
    local result2=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/70143836' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")

    if [ "${result1}" == '000' ] || [ "$result2" == '000' ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'Netflix_result' 'Unknow'
        return
    fi
    if [ "$result1" == '404' ] && [ "$result2" == '404' ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Yellow}Originals Only${Font_Suffix}\n"
        modifyJsonTemplate 'Netflix_result' 'No (Originals Only)'
        return
    fi
    if [ "$result1" == '403' ] || [ "$result2" == '403' ]; then
        echo -n -e "\r Netflix:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'Netflix_result' 'No'
        return
    fi
    if [ "$result1" == '200' ] || [ "$result2" == '200' ]; then
        local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.netflix.com/' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")
        local region=$(echo "$tmpresult" | grep -woP '"requestCountry":{"id":"\K\w\w' | head -n 1)
        echo -n -e "\r Netflix:\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        modifyJsonTemplate 'Netflix_result' 'Yes' "${region}"
        return
    fi

    echo -n -e "\r Netflix:\t\t\t\t${Font_Red}Failed (Error: ${result1}_${result2})${Font_Suffix}\n"
    modifyJsonTemplate 'Netflix_result' 'Failed' "${result1}_${result2}"
}

# DisneyPlus
MediaUnlockTest_DisneyPlus() {
    local PreAssertion=$(curl $useNIC $usePROXY $xForward -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/devices" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' 2>&1)
    if [[ "$PreAssertion" == "curl"* ]] && [[ "$1" == "6" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}IPv6 Not Support${Font_Suffix}\n"
        return
    elif [[ "$PreAssertion" == "curl"* ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'Unknow'
        return
    fi

    local assertion=$(echo $PreAssertion | python -m json.tool 2>/dev/null | grep assertion | cut -f4 -d'"')
    local PreDisneyCookie=$(echo "$Media_Cookie" | sed -n '1p')
    local disneycookie=$(echo $PreDisneyCookie | sed "s/DISNEYASSERTION/${assertion}/g")
    local TokenContent=$(curl $useNIC $usePROXY $xForward -${1} --user-agent "${UA_Browser}" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/token" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycookie" 2>&1)
    local isBanned=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'forbidden-location')
    local is403=$(echo $TokenContent | grep '403 ERROR')

    if [ -n "$isBanned" ] || [ -n "$is403" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    fi

    local fakecontent=$(echo "$Media_Cookie" | sed -n '8p')
    local refreshToken=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    local disneycontent=$(echo $fakecontent | sed "s/ILOVEDISNEY/${refreshToken}/g")
    local tmpresult=$(curl $useNIC $usePROXY $xForward -${1} --user-agent "${UA_Browser}" -X POST -sSL --max-time 10 "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycontent" 2>&1)
    local previewcheck=$(curl $useNIC $usePROXY $xForward -${1} -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://disneyplus.com" | grep preview)
    local isUnabailable=$(echo $previewcheck | grep 'unavailable')
    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')

    if [[ "$region" == "JP" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: JP)${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'Yes' 'JP'
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "false" ]] && [ -z "$isUnabailable" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Yellow}Available For [Disney+ $region] Soon${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    elif [ -n "$region" ] && [ -n "$isUnavailable" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "true" ]]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Green}Yes (Region: $region)${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'Yes' "${region}"
        return
    elif [ -z "$region" ]; then
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'No'
        return
    else
        echo -n -e "\r Disney+:\t\t\t\t${Font_Red}Failed${Font_Suffix}\n"
        modifyJsonTemplate 'DisneyPlus_result' 'Unknow'
        return
    fi

}

# YouTube Premium
MediaUnlockTest_YouTube_Premium() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.youtube.com/premium' -H 'accept-language: en-US,en;q=0.9' -H 'cookie: YSC=FSCWhKo2Zgw; VISITOR_PRIVACY_METADATA=CgJERRIEEgAgYQ%3D%3D; PREF=f7=4000; __Secure-YEC=CgtRWTBGTFExeV9Iayjele2yBjIKCgJERRIEEgAgYQ%3D%3D; SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY; VISITOR_INFO1_LIVE=Di84mAIbgKY; __Secure-BUCKET=CGQ' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'YouTube_Premium_result' 'Unknow'
        return
    fi

    local isCN=$(echo "$tmpresult" | grep 'www.google.cn')

    if [ -n "$isCN" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix} ${Font_Green}(Region: CN)${Font_Suffix}\n"
        modifyJsonTemplate 'YouTube_Premium_result' 'No' 'CN'
        return
    fi

    local isNotAvailable=$(echo "$tmpresult" | grep -i 'Premium is not available in your country')
    local region=$(echo "$tmpresult" | grep -woP '"INNERTUBE_CONTEXT_GL"\s{0,}:\s{0,}"\K[^"]+')
    local isAvailable=$(echo "$tmpresult" | grep -i 'ad-free')

    if [ -n "$isNotAvailable" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'YouTube_Premium_result' 'No'
        return
    fi
    if [ -z "$region" ]; then
        region='UNKNOWN'
    fi
    if [ -n "$isAvailable" ]; then
        echo -n -e "\r YouTube Premium:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        modifyJsonTemplate 'YouTube_Premium_result' 'Yes' "${region}"
        return
    fi

    echo -n -e "\r YouTube Premium:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
    modifyJsonTemplate 'YouTube_Premium_result' 'Unknow'
}

# HBO MAX
MediaUnlockTest_HBOMax() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sLi 'https://www.max.com/' -w "_TAG_%{http_code}_TAG_" --user-agent "${UA_BROWSER}")
    local httpCode=$(echo "$tmpresult" | grep '_TAG_' | awk -F'_TAG_' '{print $2}')
    if [ "$httpCode" == '000' ]; then
        echo -n -e "\r HBO Max:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'HBOMAX_result' 'Unknow'
        return
    fi

    local countryList=$(echo "$tmpresult" | grep -woP '"url":"/[a-z]{2}/[a-z]{2}"' | cut -f4 -d'"' | cut -f2 -d'/' | sort -n | uniq | xargs | tr a-z A-Z)
    local countryList="${countryList} US"
    local region=$(echo "$tmpresult" | grep -woP 'countryCode=\K[A-Z]{2}' | head -n 1)
    local isUnavailable=$(echo "$countryList" | grep "$region")

    if [ -z "$region" ]; then
        echo -n -e "\r HBO Max:\t\t\t\t${Font_Red}Failed (Error: Country Code Not Found)${Font_Suffix}\n"
        modifyJsonTemplate 'HBOMAX_result' 'No'
        return
    fi
    if [ -n "$isUnavailable" ]; then
        echo -n -e "\r HBO Max:\t\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        modifyJsonTemplate 'HBOMAX_result' 'Yes' "${region}"
        return
    fi

    echo -n -e "\r HBO Max:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
    modifyJsonTemplate 'HBOMAX_result' 'No'
}

# Amazon Prime Video
MediaUnlockTest_PrimeVideo() {
    if [ "${USE_IPV6}" == 1 ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}IPv6 Is Not Currently Supported${Font_Suffix}\n"
        modifyJsonTemplate 'AmazonPrime_result' 'No'
        return
    fi

    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.primevideo.com' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'AmazonPrime_result' 'Unknow'
        return
    fi

    local isBlocked=$(echo "$tmpresult" | grep -i 'isServiceRestricted')
    local region=$(echo "$tmpresult" | grep -woP '"currentTerritory":"\K[^"]+' | head -n 1)

    if [ -z "$isBlocked" ] && [ -z "$region" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        modifyJsonTemplate 'AmazonPrime_result' 'No'
        return
    fi
    if [ -n "$isBlocked" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}No (Service Not Available)${Font_Suffix}\n"
        modifyJsonTemplate 'AmazonPrime_result' 'No'
        return
    fi
    if [ -n "$region" ]; then
        echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        modifyJsonTemplate 'AmazonPrime_result' 'Yes' "${region}"
        return
    fi

    echo -n -e "\r Amazon Prime Video:\t\t\t${Font_Red}Failed (Error: Unknown Region)${Font_Suffix}\n"
    modifyJsonTemplate 'AmazonPrime_result' 'No'
}

# Spotify
MediaUnlockTest_Spotify() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -s 'https://spclient.wg.spotify.com/signup/public/v1/account' -d "birth_day=11&birth_month=11&birth_year=2000&collect_personal_info=undefined&creation_flow=&creation_point=https%3A%2F%2Fwww.spotify.com%2Fhk-en%2F&displayname=Gay%20Lord&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www&referrer=&send-email=0&thirdpartyemail=0&identifier_token=AgE6YTvEzkReHNfJpO114514" -X POST -H "Accept-Language: en" --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'Spotify_result' 'Unknow'
        return
    fi

    local statusCode=$(echo "$tmpresult" | grep -woP '"status"\s{0,}:\s{0,}\K\d+')
    local region=$(echo "$tmpresult" | grep -woP '"country"\s{0,}:\s{0,}"\K[^"]+')
    local isLaunched=$(echo "$tmpresult" | grep -woP '"is_country_launched"\s{0,}:\s{0,}\K(false|true)')

    if [ -z "$statusCode" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        modifyJsonTemplate 'Spotify_result' 'No'
        return
    fi
    if [ "$statusCode" == '320' ] || [ "$statusCode" == '120' ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'Spotify_result' 'No'
        return
    fi
    if [ -z "$isLaunched" ] || [ -z "$region" ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Error: PAGE ERROR)${Font_Suffix}\n"
        modifyJsonTemplate 'Spotify_result' 'No'
        return
    fi
    if [ "$isLaunched" == 'false' ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'Spotify_result' 'No'
        return
    fi
    if [ "$statusCode" == '311' ]; then
        echo -n -e "\r Spotify Registration:\t\t\t${Font_Green}Yes (Region: ${region})${Font_Suffix}\n"
        modifyJsonTemplate 'Spotify_result' 'Yes' "${region}"
        return
    fi

    echo -n -e "\r Spotify Registration:\t\t\t${Font_Red}Failed (Error: $statusCode)${Font_Suffix}\n"
    modifyJsonTemplate 'Spotify_result' 'No'
}

# OpenAI
MediaUnlockTest_OpenAI() {
    SUPPORT_COUNTRY=(AL DZ AD AO AG AR AM AU AT AZ BS BD BB BE BZ BJ BT BO BA BW BR BN BG BF CV CA CL CO KM CG CR CI HR CY CZ DK DJ DM DO EC SV EE FJ FI FR GA GM GE DE GH GR GD GT GN GW GY HT VA HN HU IS IN ID IQ IE IL IT JM JP JO KZ KE KI KW KG LV LB LS LR LI LT LU MG MW MY MV ML MT MH MR MU MX FM MD MC MN ME MA MZ MM NA NR NP NL NZ NI NE NG MK NO OM PK PW PS PA PG PY PE PH PL PT QA RO RW KN LC VC WS SM ST SN RS SC SL SG SK SI SB ZA KR ES LK SR SE CH TW TZ TH TL TG TO TT TN TR TV UG UA AE GB US UY VU ZM)

    local tmpresult1=$(curl ${CURL_DEFAULT_OPTS} -s 'https://api.openai.com/compliance/cookie_requirements' -H 'authority: api.openai.com' -H 'accept: */*' -H 'accept-language: en-US,en;q=0.9' -H 'authorization: Bearer null' -H 'content-type: application/json' -H 'origin: https://platform.openai.com' -H 'referer: https://platform.openai.com/' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-dest: empty' -H 'sec-fetch-mode: cors' -H 'sec-fetch-site: same-site' --user-agent "${UA_BROWSER}")
    local tmpresult2=$(curl ${CURL_DEFAULT_OPTS} -s 'https://ios.chat.openai.com/' -H 'authority: ios.chat.openai.com' -H 'accept: */*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-dest: document' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-site: none' -H 'sec-fetch-user: ?1' -H 'upgrade-insecure-requests: 1' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult1" ]; then
        echo -n -e "\r OpenAI:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'OpenAI_result' 'Unknow'
        return
    fi
    if [ -z "$tmpresult2" ]; then
        echo -n -e "\r OpenAI:\t\t\t\t${Font_Red}Failed (Network Connection)${Font_Suffix}\n"
        modifyJsonTemplate 'OpenAI_result' 'Unknow'
        return
    fi

    local result1=$(echo "$tmpresult1" | grep -i 'unsupported_country')
    local result2=$(echo "$tmpresult2" | grep -i 'VPN')
    if [ -z "$result2" ] && [ -z "$result1" ]; then
        local ipv4_supported=$(ping 1.1.1.1 -c 1 2>&1)
        local ipv6_supported=$(ping6 2606:4700:4700::1111 -c 1 2>&1)

        if [[ "$ipv4_supported" != *"received"* ]] && [[ "$ipv4_supported" != *"transmitted"* ]] && [[ "$ipv6_supported" != *"received"* ]] && [[ "$ipv6_supported" != *"transmitted"* ]]; then
            echo -n -e "\r OpenAI:\t\t\t\t${Font_Yellow}IPv4 and IPv6 are not supported on the current host. Skip...${Font_Suffix}\n"
            modifyJsonTemplate 'OpenAI_result' 'IPv4 and IPv6 not supported'
            return
        fi
        
        if [[ "$ipv4_supported" == *"received"* ]] || [[ "$ipv4_supported" == *"transmitted"* ]]; then
            local_ipv4=$(curl -4 -sS https://chat.openai.com/cdn-cgi/trace | grep "ip=" | awk -F= '{print $2}')
            iso2_code4=$(curl -4 -sS https://chat.openai.com/cdn-cgi/trace | grep "loc=" | awk -F= '{print $2}')
            
            if [ -z "$iso2_code4" ]; then
                iso2_code4="UNKNOWN"
            fi
            
            if [[ " ${SUPPORT_COUNTRY[@]} " =~ " ${iso2_code4} " ]]; then
                echo -n -e "\r OpenAI:\t\t\t\t${Font_Green}Yes (Region: ${iso2_code4})${Font_Suffix}\n"
                modifyJsonTemplate 'OpenAI_result' 'Yes' "${iso2_code4}"
            else
                echo -n -e "\r OpenAI:\t\t\t\t${Font_Red}No (Region: ${iso2_code4})${Font_Suffix}\n"
                modifyJsonTemplate 'OpenAI_result' 'No' "${iso2_code4}"
            fi
            return
        fi

        if [[ "$ipv6_supported" == *"received"* ]] || [[ "$ipv6_supported" == *"transmitted"* ]]; then
            local_ipv6=$(curl -6 -sS https://chat.openai.com/cdn-cgi/trace | grep "ip=" | awk -F= '{print $2}')
            iso2_code6=$(curl -6 -sS https://chat.openai.com/cdn-cgi/trace | grep "loc=" | awk -F= '{print $2}')
            
            if [ -z "$iso2_code6" ]; then
                iso2_code6="UNKNOWN"
            fi
            
            if [[ " ${SUPPORT_COUNTRY[@]} " =~ " ${iso2_code6} " ]]; then
                echo -n -e "\r OpenAI:\t\t\t\t${Font_Green}Yes (Region: ${iso2_code6})${Font_Suffix}\n"
                modifyJsonTemplate 'OpenAI_result' 'Yes' "${iso2_code6}"
            else
                echo -n -e "\r OpenAI:\t\t\t\t${Font_Red}No (Region: ${iso2_code6})${Font_Suffix}\n"
                modifyJsonTemplate 'OpenAI_result' 'No' "${iso2_code6}"
            fi
            return
        fi
    fi

    if [ -n "$result2" ] && [ -n "$result1" ]; then
        echo -n -e "\r OpenAI:\t\t\t\t${Font_Red}No${Font_Suffix}\n"
        modifyJsonTemplate 'OpenAI_result' 'No'
        return
    fi
    if [ -z "$result1" ] && [ -n "$result2" ]; then
        echo -n -e "\r OpenAI:\t\t\t\t${Font_Yellow}No (Only Available with Web Browser)${Font_Suffix}\n"
        modifyJsonTemplate 'OpenAI_result' 'No'
        return
    fi
    if [ -n "$result1" ] && [ -z "$result2" ]; then
        echo -n -e "\r OpenAI:\t\t\t\t${Font_Yellow}No (Only Available with Mobile APP)${Font_Suffix}\n"
        modifyJsonTemplate 'OpenAI_result' 'No'
        return
    fi

    echo -n -e "\r OpenAI:\t\t\t\t${Font_Red}Failed (Error: Unknown)${Font_Suffix}\n"
    modifyJsonTemplate 'OpenAI_result' 'Unknow'
}

###########################################
#                                         #
#   sspanel unlock check function code    #
#                                         #
###########################################

createJsonTemplate() {
    echo '{
    "YouTube": "YouTube_Premium_result",
    "Netflix": "Netflix_result",
    "DisneyPlus": "DisneyPlus_result",
    "HBOMAX": "HBOMAX_result",
    "AmazonPrime": "AmazonPrime_result",
    "Spotify": "Spotify_result",
    "OpenAI": "OpenAI_result"
}' > /root/media_test_tpl.json
}

modifyJsonTemplate() {
    key_word=$1
    result=$2
    region=$3

    if [[ "$3" == "" ]]; then
        sed -i "s#${key_word}#${result}#g" /root/media_test_tpl.json
    else
        sed -i "s#${key_word}#${result} (${region})#g" /root/media_test_tpl.json
    fi
}

setCronTask() {
    addTask() {
        execution_time_interval=$1

        crontab -l >/root/crontab.list
        echo "0 */${execution_time_interval} * * * /bin/bash /root/csm.sh" >>/root/crontab.list
        crontab /root/crontab.list
        rm -rf /root/crontab.list
        echo -e "$(green) The scheduled task is added successfully."
    }

    crontab -l | grep "csm.sh" >/dev/null
    if [[ "$?" != "0" ]]; then
        echo "[1] 1 hour"
        echo "[2] 2 hour"
        echo "[3] 3 hour"
        echo "[4] 4 hour"
        echo "[5] 6 hour"
        echo "[6] 8 hour"
        echo "[7] 12 hour"
        echo "[8] 24 hour"
        echo
        read -p "$(blue) Please select the detection frequency and enter the serial number (eg: 1):" time_interval_id

        if [[ "${time_interval_id}" == "5" ]];then
            time_interval=6
        elif [[ "${time_interval_id}" == "6" ]];then
            time_interval=8
        elif [[ "${time_interval_id}" == "7" ]];then
            time_interval=12
        elif [[ "${time_interval_id}" == "8" ]];then
            time_interval=24
        else
            time_interval=$time_interval_id
        fi

        case "${time_interval_id}" in
            [1-8])
                addTask ${time_interval};;
            *)
                echo -e "$(red) Choose one from the list given and enter the sequence number."
                exit;;
        esac
    fi
}

checkConfig() {
    getConfig() {
        read -p "$(blue) Please enter the panel address (eg: https://demo.sspanel.org):" panel_address
        read -p "$(blue) Please enter the mu key:" mu_key
        read -p "$(blue) Please enter the node id:" node_id

        if [[ "${panel_address}" = "" ]] || [[ "${mu_key}" = "" ]];then
            echo -e "$(red) Complete all necessary parameter entries."
            exit
        fi

        curl -s "${panel_address}/mod_mu/nodes?key=${mu_key}" | grep "invalid" > /dev/null
        if [[ "$?" = "0" ]];then
            echo -e "$(red) Wrong website address or mukey error, please try again."
            exit
        fi

        echo "${panel_address}" > /root/.csm.config
        echo "${mu_key}" >> /root/.csm.config
        echo "${node_id}" >> /root/.csm.config
    }

    if [[ ! -e "/root/.csm.config" ]];then
        getConfig
    fi
}

postData() {
    if [[ ! -e "/root/.csm.config" ]];then
        echo -e "$(red) Missing configuration file."
        exit
    fi
    if [[ ! -e "/root/media_test_tpl.json" ]];then
        echo -e "$(red) Missing detection report."
        exit
    fi

    panel_address=$(sed -n 1p /root/.csm.config)
    mu_key=$(sed -n 2p /root/.csm.config)
    node_id=$(sed -n 3p /root/.csm.config)

    curl -s -X POST -d "content=$(cat /root/media_test_tpl.json | base64 | xargs echo -n | sed 's# ##g')" "${panel_address}/mod_mu/media/save_report?key=${mu_key}&node_id=${node_id}" > /root/.csm.response
    if [[ "$(cat /root/.csm.response)" != "ok" ]];then
        curl -s -X POST -d "content=$(cat /root/media_test_tpl.json | base64 | xargs echo -n | sed 's# ##g')" "${panel_address}/mod_mu/media/saveReport?key=${mu_key}&node_id=${node_id}" > /root/.csm.response
    fi

    rm -rf /root/media_test_tpl.json /root/.csm.response
}

printInfo() {
    green_start='\033[32m'
    color_end='\033[0m'

    echo
    echo -e "${green_start}The code for this script to detect streaming media unlocking is all from the open source project https://github.com/lmc999/RegionRestrictionCheck , and the open source protocol is AGPL-3.0. This script is open source as required by the open source license. Thanks to the original author @lmc999 and everyone who made the pull request for this project for their contributions.${color_end}"
    echo
    echo -e "${green_start}Project: https://github.com/ecyecy/check-stream-media${color_end}"
    echo -e "${green_start}Version: 2024-07-15 v.3.0${color_end}"
    echo -e "${green_start}Author: @ecyecy${color_end}"
}

runCheck() {
    createJsonTemplate
    MediaUnlockTest_Netflix 4
    MediaUnlockTest_YouTube_Premium 4
    MediaUnlockTest_DisneyPlus 4
    MediaUnlockTest_HBOMax 4
    MediaUnlockTest_PrimeVideo 4
    MediaUnlockTest_Spotify 4
    MediaUnlockTest_OpenAI 4
}

checkData()
{
    counter=0
    max_check_num=3
    cat /root/media_test_tpl.json | grep "_result" > /dev/null
    until [ $? != '0' ]  || [[ ${counter} -ge ${max_check_num} ]]
    do
        sleep 1
        runCheck > /dev/null
        echo -e "\033[33mThere is something wrong with the data and it is being retested for the ${counter} time...\033[0m"
        counter=$(expr ${counter} + 1)
    done
}

main() {
    echo
    checkOS
    checkCPU
    checkDependencies
    setCronTask
    checkConfig
    runCheck
    checkData
    postData
    printInfo
}

main
