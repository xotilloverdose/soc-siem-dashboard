import folium

# -------------------------
# CREATE MAP
# -------------------------

attack_map = folium.Map(
    location=[20, 0],
    zoom_start=2
)

# -------------------------
# ATTACK DATA
# -------------------------

attacks = [

    {
        "ip": "8.8.8.8",
        "country": "United States",
        "coords": [37.0902, -95.7129],
        "color": "red"
    },

    {
        "ip": "103.44.12.9",
        "country": "India",
        "coords": [20.5937, 78.9629],
        "color": "orange"
    },

    {
        "ip": "45.12.33.10",
        "country": "Germany",
        "coords": [51.1657, 10.4515],
        "color": "blue"
    },

    {
        "ip": "77.88.99.11",
        "country": "Russia",
        "coords": [61.5240, 105.3188],
        "color": "darkred"
    },

    {
        "ip": "88.21.77.3",
        "country": "Russia",
        "coords": [55.7558, 37.6176],
        "color": "purple"
    },

    {
        "ip": "192.168.1.10",
        "country": "Local Network",
        "coords": [19.0760, 72.8777],
        "color": "green"
    }

]

# -------------------------
# ADD MARKERS
# -------------------------

for attack in attacks:

    folium.CircleMarker(

        location=attack["coords"],

        radius=12,

        popup=f"""
        IP: {attack['ip']}
        <br>
        Country: {attack['country']}
        """,

        color=attack["color"],

        fill=True,

        fill_color=attack["color"]

    ).add_to(attack_map)

# -------------------------
# SAVE MAP
# -------------------------

attack_map.save("attack_map.html")

print("🌍 Advanced attack map generated!")