FEEDS = [
    # =========================================================
    # GOVERNMENT / NATIONAL CYBERSECURITY
    # =========================================================
    {
        "name": "UK NCSC - Threat Reports",
        "url": (
            "https://www.ncsc.gov.uk/api/1/services/"
            "v1/report-rss-feed.xml"
        ),
        "category": "government",
        "enabled": True,
    },
    {
        "name": "CERT/CC Vulnerability Notes",
        "url": "https://kb.cert.org/vuls/atomfeed/",
        "category": "government",
        "enabled": True,
    },

    # =========================================================
    # CYBERSECURITY NEWS
    # =========================================================
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "news",
        "enabled": True,
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "category": "news",
        "enabled": True,
    },
    {
        "name": "The Hacker News",
        "url": (
            "https://feeds.feedburner.com/"
            "TheHackersNews"
        ),
        "category": "news",
        "enabled": True,
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "news",
        "enabled": True,
    },
    {
        "name": "KrebsOnSecurity",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "news",
        "enabled": True,
    },
    {
        "name": "The Record",
        "url": "https://therecord.media/feed/",
        "category": "news",
        "enabled": True,
    },
    {
        "name": "CyberScoop",
        "url": "https://cyberscoop.com/feed/",
        "category": "news",
        "enabled": True,
    },

    # =========================================================
    # THREAT RESEARCH / VENDOR INTELLIGENCE
    # =========================================================
    {
        "name": "Cisco Talos Intelligence",
        "url": (
            "https://blog.talosintelligence.com/"
            "rss/"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "Palo Alto Unit 42",
        "url": (
            "https://unit42.paloaltonetworks.com/"
            "feed/"
        ),
        "category": "research",
        "enabled": True,
    },

    # Google publishes this Threat Intelligence RSS feed from
    # its official Threat Intelligence / Mandiant blog page.
    # The feed was validated locally:
    # HTTP 200, 20 entries, valid publication timestamps.
    {
        "name": "Google Threat Intelligence / Mandiant",
        "url": (
            "https://feeds.feedburner.com/"
            "threatintelligence/pvexyqv7v0v"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "Google Project Zero",
        "url": (
            "https://googleprojectzero.blogspot.com/"
            "feeds/posts/default?alt=rss"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "Microsoft Security Blog",
        "url": (
            "https://www.microsoft.com/"
            "en-us/security/blog/feed/"
        ),
        "category": "vendor",
        "enabled": True,
    },
    {
        "name": "CrowdStrike Counter Adversary Operations",
        "url": (
            "https://www.crowdstrike.com/"
            "en-us/blog/feed"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "SentinelLabs",
        "url": (
            "https://www.sentinelone.com/"
            "labs/feed/"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "ESET WeLiveSecurity",
        "url": (
            "https://www.welivesecurity.com/"
            "en/rss/feed/"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "Check Point Research",
        "url": (
            "https://research.checkpoint.com/feed/"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "Proofpoint Threat Insight",
        "url": (
            "https://www.proofpoint.com/"
            "us/rss.xml"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "Elastic Security Labs",
        "url": (
            "https://www.elastic.co/"
            "security-labs/rss/feed.xml"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "SANS Internet Storm Center",
        "url": (
            "https://isc.sans.edu/"
            "rssfeed.xml"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "The DFIR Report",
        "url": (
            "https://thedfirreport.com/feed/"
        ),
        "category": "research",
        "enabled": True,
    },
    {
        "name": "Rapid7 Research",
        "url": (
            "https://blog.rapid7.com/rss/"
        ),
        "category": "research",
        "enabled": True,
    },
]


# =============================================================
# COMPLETE TARGET INTELLIGENCE REGISTRY
# =============================================================

TARGET_SOURCES = [
    {
        "name": "CISA Cybersecurity Advisories",
        "category": "government",
        "status": "pending",
    },
    {
        "name": "CISA KEV",
        "category": "government",
        "status": "enrichment",
    },
    {
        "name": "NVD",
        "category": "government",
        "status": "enrichment",
    },
    {
        "name": "UK NCSC",
        "category": "government",
        "status": "enabled",
    },
    {
        "name": "CERT/CC Vulnerability Notes",
        "category": "government",
        "status": "enabled",
    },
    {
        "name": "BleepingComputer",
        "category": "news",
        "status": "enabled",
    },
    {
        "name": "The Hacker News",
        "category": "news",
        "status": "enabled",
    },
    {
        "name": "SecurityWeek",
        "category": "news",
        "status": "enabled",
    },
    {
        "name": "Dark Reading",
        "category": "news",
        "status": "enabled",
    },
    {
        "name": "KrebsOnSecurity",
        "category": "news",
        "status": "enabled",
    },
    {
        "name": "The Record",
        "category": "news",
        "status": "enabled",
    },
    {
        "name": "CyberScoop",
        "category": "news",
        "status": "enabled",
    },
    {
        "name": "Cisco Talos Intelligence",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Palo Alto Unit 42",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Google Threat Intelligence / Mandiant",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Google Project Zero",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Microsoft Security Blog",
        "category": "vendor",
        "status": "enabled",
    },

    # The automatically discovered MSRC /feed/ endpoint returned
    # a "Content Not Found" entry rather than useful advisories.
    # Keep MSRC pending until a reliable supported source is found.
    {
        "name": "MSRC",
        "category": "vendor",
        "status": "pending",
    },
    {
        "name": "CrowdStrike Counter Adversary Operations",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "SentinelLabs",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "ESET WeLiveSecurity",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Sophos X-Ops",
        "category": "research",
        "status": "pending",
    },
    {
        "name": "Trend Micro Research",
        "category": "research",
        "status": "pending",
    },
    {
        "name": "Check Point Research",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Fortinet FortiGuard Labs",
        "category": "research",
        "status": "pending",
    },
    {
        "name": "Proofpoint Threat Insight",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Elastic Security Labs",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "SANS Internet Storm Center",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "The DFIR Report",
        "category": "research",
        "status": "enabled",
    },
    {
        "name": "Rapid7 Research",
        "category": "research",
        "status": "enabled",
    },
]


def get_enabled_feeds():
    return [
        source
        for source in FEEDS
        if source.get(
            "enabled",
            True,
        )
    ]


def get_target_sources():
    return list(
        TARGET_SOURCES
    )


def get_source_counts():
    enabled = sum(
        1
        for source in TARGET_SOURCES
        if source["status"] == "enabled"
    )

    enrichment = sum(
        1
        for source in TARGET_SOURCES
        if source["status"] == "enrichment"
    )

    pending = sum(
        1
        for source in TARGET_SOURCES
        if source["status"] == "pending"
    )

    return {
        "total": len(TARGET_SOURCES),
        "enabled": enabled,
        "enrichment": enrichment,
        "pending": pending,
    }