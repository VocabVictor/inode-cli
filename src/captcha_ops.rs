//! nano-CNN 用到的纯数值算子（卷积、池化、激活、旋转、缩放）。

use crate::captcha_cnn::{GH, GW, Tensor};

pub(crate) fn softmax(x: &[f32]) -> Vec<f32> {
    let m = x.iter().cloned().fold(f32::MIN, f32::max);
    let e: Vec<f32> = x.iter().map(|v| (v - m).exp()).collect();
    let s: f32 = e.iter().sum();
    e.iter().map(|v| v / s).collect()
}
pub(crate) fn relu(x: &[f32]) -> Vec<f32> {
    x.iter().map(|v| v.max(0.0)).collect()
}

/// conv 3x3 pad1 same-size. 输入 cin x h x w，权重 (cout,cin,3,3)，输出 cout x h x w（扁平）。
pub(crate) fn conv(x: &[f32], cin: usize, h: usize, w: usize, wt: &Tensor, b: &Tensor) -> Vec<f32> {
    let cout = wt.shape[0];
    let mut out = vec![0f32; cout * h * w];
    for oc in 0..cout {
        for oy in 0..h {
            for ox in 0..w {
                let mut acc = b.data[oc];
                for ic in 0..cin {
                    for ky in 0..3usize {
                        let iy = oy as isize + ky as isize - 1;
                        if iy < 0 || iy >= h as isize {
                            continue;
                        }
                        for kx in 0..3usize {
                            let ix = ox as isize + kx as isize - 1;
                            if ix < 0 || ix >= w as isize {
                                continue;
                            }
                            let xv = x[(ic * h + iy as usize) * w + ix as usize];
                            let wv = wt.data[((oc * cin + ic) * 3 + ky) * 3 + kx];
                            acc += xv * wv;
                        }
                    }
                }
                out[(oc * h + oy) * w + ox] = acc;
            }
        }
    }
    out
}

/// 2x2 maxpool, 输入 c x h x w -> c x (h/2) x (w/2)（扁平）
pub(crate) fn maxpool2(x: &[f32], c: usize, h: usize, w: usize) -> Vec<f32> {
    let h2 = h / 2;
    let w2 = w / 2;
    let mut out = vec![0f32; c * h2 * w2];
    for ch in 0..c {
        for oy in 0..h2 {
            for ox in 0..w2 {
                let mut m = f32::MIN;
                for dy in 0..2 {
                    for dx in 0..2 {
                        let v = x[(ch * h + oy * 2 + dy) * w + ox * 2 + dx];
                        if v > m {
                            m = v;
                        }
                    }
                }
                out[(ch * h2 + oy) * w2 + ox] = m;
            }
        }
    }
    out
}

/// 绕中心旋转 deg 度（双线性，同尺寸，越界填 0）
pub(crate) fn rotate(g: &[f32], deg: f32) -> Vec<f32> {
    let a = deg.to_radians();
    let (ca, sa) = (a.cos(), a.sin());
    let (cx, cy) = ((GW as f32 - 1.0) / 2.0, (GH as f32 - 1.0) / 2.0);
    let mut out = vec![0f32; GH * GW];
    for oy in 0..GH {
        for ox in 0..GW {
            let dx = ox as f32 - cx;
            let dy = oy as f32 - cy;
            let sx = dx * ca + dy * sa + cx;
            let sy = -dx * sa + dy * ca + cy;
            if sx < 0.0 || sx > (GW - 1) as f32 || sy < 0.0 || sy > (GH - 1) as f32 {
                continue;
            }
            let x0 = sx.floor() as usize;
            let y0 = sy.floor() as usize;
            let x1 = (x0 + 1).min(GW - 1);
            let y1 = (y0 + 1).min(GH - 1);
            let fx = sx - x0 as f32;
            let fy = sy - y0 as f32;
            let v = g[y0 * GW + x0] * (1.0 - fx) * (1.0 - fy)
                + g[y0 * GW + x1] * fx * (1.0 - fy)
                + g[y1 * GW + x0] * (1.0 - fx) * fy
                + g[y1 * GW + x1] * fx * fy;
            out[oy * GW + ox] = v;
        }
    }
    out
}

/// 双线性缩放（PIL 风格：以像素中心映射）
pub(crate) fn resize_bilinear(src: &[f32], sw: usize, sh: usize, dw: usize, dh: usize) -> Vec<f32> {
    let mut out = vec![0f32; dw * dh];
    let sx = sw as f32 / dw as f32;
    let sy = sh as f32 / dh as f32;
    for oy in 0..dh {
        let fy = (oy as f32 + 0.5) * sy - 0.5;
        let y0 = fy.floor();
        let wy = fy - y0;
        let y0i = y0.max(0.0) as usize;
        let y1i = ((y0 as isize + 1).max(0) as usize).min(sh - 1);
        let y0i = y0i.min(sh - 1);
        for ox in 0..dw {
            let fx = (ox as f32 + 0.5) * sx - 0.5;
            let x0 = fx.floor();
            let wx = fx - x0;
            let x0i = (x0.max(0.0) as usize).min(sw - 1);
            let x1i = ((x0 as isize + 1).max(0) as usize).min(sw - 1);
            let v = src[y0i * sw + x0i] * (1.0 - wx) * (1.0 - wy)
                + src[y0i * sw + x1i] * wx * (1.0 - wy)
                + src[y1i * sw + x0i] * (1.0 - wx) * wy
                + src[y1i * sw + x1i] * wx * wy;
            out[oy * dw + ox] = v;
        }
    }
    out
}
