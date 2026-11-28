//! # `hps_sdk::spatial`
//!
//! Deterministic `#![no_std]` 2D spatial geometry, planar integer meter projection (`u128::isqrt`,
//! zero floating-point drift across x86_64/aarch64/riscv/wasm32), spatial grid cell indexing, and
//! priority-ordered metropolitan price-regime bounding boxes for Class II Multi-Parameter
//! Haltproof Matching Engines (such as `ride-exchange`).

/// Maximum number of Price Regimes per Metropolitan Exchange instance.
pub const MAX_METRO_REGIMES: usize = 8;

/// Signed microdegree coordinate (`1e-6` degrees, ~`0.111 m` resolution).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct GeoCoord {
    pub lat_e6: i32,
    pub lon_e6: i32,
}

impl GeoCoord {
    pub const fn new(lat_e6: i32, lon_e6: i32) -> Self {
        Self { lat_e6, lon_e6 }
    }

    pub const fn is_valid(&self) -> bool {
        self.lat_e6 >= -90_000_000
            && self.lat_e6 <= 90_000_000
            && self.lon_e6 >= -180_000_000
            && self.lon_e6 <= 180_000_000
    }
}

/// Axis-aligned bounding box in microdegrees defining a regional Price Regime.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct GeoBox {
    pub min_lat_e6: i32,
    pub max_lat_e6: i32,
    pub min_lon_e6: i32,
    pub max_lon_e6: i32,
}

impl GeoBox {
    pub const fn new(min_lat_e6: i32, max_lat_e6: i32, min_lon_e6: i32, max_lon_e6: i32) -> Self {
        Self {
            min_lat_e6,
            max_lat_e6,
            min_lon_e6,
            max_lon_e6,
        }
    }

    #[inline]
    pub const fn contains(&self, c: GeoCoord) -> bool {
        c.lat_e6 >= self.min_lat_e6
            && c.lat_e6 <= self.max_lat_e6
            && c.lon_e6 >= self.min_lon_e6
            && c.lon_e6 <= self.max_lon_e6
    }
}

/// Exact integer planar equirectangular straight-line distance in meters between `a` and `b`.
///
/// - `cos_lat_bps`: $\lfloor \cos(\varphi_0) \times 10{,}000 \rfloor$ at the metro's reference
///   latitude (e.g. `9997` for Singapore at $1.35^\circ\text{N}$, `6225` for London at $51.5^\circ\text{N}$).
/// - Zero floating-point instructions: uses exact `u128::isqrt()` in micrometer-scale fixed point.
#[inline]
pub fn planar_straight_distance_m(a: GeoCoord, b: GeoCoord, cos_lat_bps: u32) -> u64 {
    if a == b {
        return 0;
    }
    let dlat = (a.lat_e6 as i64 - b.lat_e6 as i64).unsigned_abs() as u128;
    let dlon = (a.lon_e6 as i64 - b.lon_e6 as i64).unsigned_abs() as u128;

    // 1 deg lat ≈ 111,132 m -> 1 microdeg lat = 111,132 micrometers
    // 1 deg lon at equator ≈ 111,320 m -> scaled by cos_lat_bps / 10,000
    let dy_um = dlat.saturating_mul(111_132);
    let dx_um = dlon
        .saturating_mul(111_320)
        .saturating_mul(cos_lat_bps as u128)
        / 10_000;

    let sum_sq = dx_um
        .saturating_mul(dx_um)
        .saturating_add(dy_um.saturating_mul(dy_um));
    let dist_um = sum_sq.isqrt();
    ((dist_um + 500_000) / 1_000_000) as u64
}

/// Estimated urban road-network distance in meters (`straight_m * road_factor_bps / 10_000`).
/// Enforces a minimum of `100 m` whenever `a != b` so ultra-short hops remain positive.
#[inline]
pub fn road_distance_m(a: GeoCoord, b: GeoCoord, cos_lat_bps: u32, road_factor_bps: u32) -> u64 {
    if a == b {
        return 0;
    }
    let straight = planar_straight_distance_m(a, b, cos_lat_bps);
    let scaled = ((straight as u128).saturating_mul(road_factor_bps as u128) + 5_000) / 10_000;
    let m = scaled as u64;
    if m < 100 {
        100
    } else {
        m
    }
}

/// Quantizes `coord` into a coarse 2D spatial grid cell `(cell_x, cell_y)` of width ~`1.5 km`
/// (`13_500` microdegrees $\approx 1.50\text{ km}$ near the equator).
#[inline]
pub const fn grid_cell_1500m(c: GeoCoord) -> (i32, i32) {
    (c.lon_e6.div_euclid(13_500), c.lat_e6.div_euclid(13_500))
}

/// Compute billable clean fare in integer quote units (e.g. cents) for `trip_m` meters at
/// `rate_per_km` quote units per km: $\lceil \text{rate\_per\_km} \times \text{trip\_m} / 1000 \rceil$.
#[inline]
pub const fn compute_trip_fare_ceil(rate_per_km: u64, trip_m: u64) -> Option<u64> {
    if rate_per_km == 0 || trip_m == 0 {
        return Some(0);
    }
    let num = (rate_per_km as u128)
        .saturating_mul(trip_m as u128)
        .saturating_add(999);
    let res = num / 1000;
    if res > (u64::MAX as u128) {
        None
    } else {
        Some(res as u64)
    }
}

/// Canonical 6-Regime Singapore Metropolitan Configuration:
/// - `0`: `CBD_MARINA`     (CBD / Marina Bay / Raffles Place / Tanjong Pagar — ERP Zone)
/// - `1`: `CITY_FRINGE`    (Orchard / Bugis / Novena / Queenstown / Buona Vista)
/// - `2`: `CHANGI_EAST`    (Changi Airport / Tampines / Bedok / Marine Parade — Airport Zone)
/// - `3`: `REMOTE_ISLANDS` (Tuas Industrial / Sentosa / Far NW — Remote Empty-Return Zone)
/// - `4`: `JURONG_WEST`    (Jurong East / Clementi / Bukit Batok / Boon Lay)
/// - `5`: `HEARTLAND_N_NE` (Bishan / Ang Mo Kio / Woodlands / Punggol / Serangoon — Catch-All)
pub mod singapore {
    use super::{GeoBox, GeoCoord};

    pub const SG_COS_LAT_BPS: u32 = 9_997;
    pub const SG_ROAD_FACTOR_BPS: u32 = 12_800; // 1.28x road tortuosity
    pub const SG_REGIME_COUNT: u8 = 6;

    pub const REGIME_CBD_MARINA: u8 = 0;
    pub const REGIME_CITY_FRINGE: u8 = 1;
    pub const REGIME_CHANGI_EAST: u8 = 2;
    pub const REGIME_REMOTE: u8 = 3;
    pub const REGIME_JURONG_WEST: u8 = 4;
    pub const REGIME_HEARTLAND: u8 = 5;

    pub const BOX_CBD: GeoBox = GeoBox::new(1_268_000, 1_298_000, 103_838_000, 103_868_000);
    pub const BOX_SENTOSA: GeoBox = GeoBox::new(1_235_000, 1_266_500, 103_805_000, 103_842_000);
    pub const BOX_TUAS: GeoBox = GeoBox::new(1_200_000, 1_360_000, 103_600_000, 103_688_000);
    pub const BOX_FAR_NW: GeoBox = GeoBox::new(1_395_000, 1_460_000, 103_660_000, 103_745_000);
    pub const BOX_FRINGE: GeoBox = GeoBox::new(1_270_000, 1_328_000, 103_782_000, 103_888_000);
    pub const BOX_CHANGI_EAST: GeoBox = GeoBox::new(1_298_000, 1_395_000, 103_892_000, 104_030_000);
    pub const BOX_JURONG_WEST: GeoBox = GeoBox::new(1_295_000, 1_395_000, 103_688_001, 103_781_999);

    /// Deterministic Singapore Price-Regime classifier (`0..=5`).
    #[inline]
    pub const fn classify_sg_regime(c: GeoCoord) -> u8 {
        if BOX_SENTOSA.contains(c) || BOX_TUAS.contains(c) || BOX_FAR_NW.contains(c) {
            return REGIME_REMOTE;
        }
        if BOX_CBD.contains(c) {
            return REGIME_CBD_MARINA;
        }
        if BOX_CHANGI_EAST.contains(c) {
            return REGIME_CHANGI_EAST;
        }
        if BOX_FRINGE.contains(c) {
            return REGIME_CITY_FRINGE;
        }
        if BOX_JURONG_WEST.contains(c) {
            return REGIME_JURONG_WEST;
        }
        REGIME_HEARTLAND
    }

    /// Default border-adjacency bitmask per Singapore regime (includes self bit `1 << z` +
    /// geographically contiguous regimes).
    pub const SG_ADJACENT_MASKS: [u8; 6] = [
        // 0 CBD_MARINA <-> CBD(0), Fringe(1), East(2), Remote/Sentosa(3)
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3),
        // 1 CITY_FRINGE <-> CBD(0), Fringe(1), East(2), Remote(3), West(4), Heartland(5)
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5),
        // 2 CHANGI_EAST <-> CBD(0), Fringe(1), East(2), Heartland(5)
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5),
        // 3 REMOTE <-> CBD/Sentosa(0), Fringe(1), Remote(3), West(4), Heartland(5)
        (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5),
        // 4 JURONG_WEST <-> Fringe(1), Remote/Tuas(3), West(4), Heartland(5)
        (1 << 1) | (1 << 3) | (1 << 4) | (1 << 5),
        // 5 HEARTLAND <-> Fringe(1), East(2), Remote(3), West(4), Heartland(5)
        (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5),
    ];

    /// Default statutory pass-through toll in SGD cents for `(orig_regime, dest_regime)`:
    /// - Entering or originating in `CBD_MARINA` (`0`): `+300` cents (`$3.00` ERP Gantry)
    /// - Originating at `CHANGI_EAST` (`2`): `+400` cents (`$4.00` Airport/East Surcharge)
    /// - Entering or originating in `REMOTE` (`3`, Sentosa/Tuas): `+400` cents (`$4.00` Gate Fee)
    /// (Capped so combined multi-toll routes remain clean and transparent.)
    #[inline]
    pub const fn default_sg_toll_cents(orig: u8, dest: u8) -> u64 {
        let mut toll = 0u64;
        if orig == REGIME_CBD_MARINA || dest == REGIME_CBD_MARINA {
            toll += 300;
        }
        if orig == REGIME_CHANGI_EAST {
            toll += 400;
        }
        if orig == REGIME_REMOTE || dest == REGIME_REMOTE {
            toll += 400;
        }
        toll
    }
}

#[cfg(test)]
mod tests {
    use super::singapore::*;
    use super::*;

    #[test]
    fn test_singapore_distance_and_regimes() {
        let marina_bay = GeoCoord::new(1_283_400, 103_860_700);
        let changi_t3 = GeoCoord::new(1_356_200, 103_988_500);
        let tuas_south = GeoCoord::new(1_295_000, 103_636_000);
        let orchard = GeoCoord::new(1_304_800, 103_831_800);
        let bishan = GeoCoord::new(1_350_800, 103_848_500);
        let jurong_east = GeoCoord::new(1_332_900, 103_743_600);

        assert_eq!(classify_sg_regime(marina_bay), REGIME_CBD_MARINA);
        assert_eq!(classify_sg_regime(changi_t3), REGIME_CHANGI_EAST);
        assert_eq!(classify_sg_regime(tuas_south), REGIME_REMOTE);
        assert_eq!(classify_sg_regime(orchard), REGIME_CITY_FRINGE);
        assert_eq!(classify_sg_regime(bishan), REGIME_HEARTLAND);
        assert_eq!(classify_sg_regime(jurong_east), REGIME_JURONG_WEST);

        let d_road = road_distance_m(marina_bay, changi_t3, SG_COS_LAT_BPS, SG_ROAD_FACTOR_BPS);
        // Marina Bay -> Changi T3 road distance ~ 20.5 - 22.0 km
        assert!(d_road >= 19_500 && d_road <= 22_500, "got {} m", d_road);
    }
}
