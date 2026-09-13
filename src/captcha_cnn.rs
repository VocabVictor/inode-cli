//! 纯 Rust 验证码识别：连通域分割 + nano-CNN(权重内嵌) + TTA + 置信度。
//! 复刻 Python(dip.py + cnn3.npz)的前处理与前向，供自动登录使用。

use crate::captcha_ops::{conv, maxpool2, relu, resize_bilinear, rotate, softmax};

pub(crate) const GW: usize = 20; // 归一宽
pub(crate) const GH: usize = 28; // 归一高
const MODEL: &[u8] = include_bytes!("captcha_model.bin");

pub(crate) struct Tensor {
    pub(crate) shape: Vec<usize>,
    pub(crate) data: Vec<f32>,
}

pub struct Model {
    alphabet: Vec<char>,
    c1w: Tensor, // (8,1,3,3)
    c1b: Tensor, // (8,)
    c2w: Tensor, // (16,8,3,3)
    c2b: Tensor, // (16,)
    fcw: Tensor, // (560,24)
    fcb: Tensor, // (24,)
}

fn rd_u32(b: &[u8], p: &mut usize) -> usize {
    let v = u32::from_le_bytes([b[*p], b[*p + 1], b[*p + 2], b[*p + 3]]) as usize;
    *p += 4;
    v
}
fn rd_tensor(b: &[u8], p: &mut usize) -> Tensor {
    let nd = rd_u32(b, p);
    let mut shape = Vec::with_capacity(nd);
    let mut n = 1usize;
    for _ in 0..nd {
        let d = rd_u32(b, p);
        shape.push(d);
        n *= d;
    }
    let mut data = Vec::with_capacity(n);
    for _ in 0..n {
        data.push(f32::from_le_bytes([b[*p], b[*p + 1], b[*p + 2], b[*p + 3]]));
        *p += 4;
    }
    Tensor { shape, data }
}

impl Model {
    pub fn load() -> Model {
        let b = MODEL;
        let mut p = 0usize;
        let al = rd_u32(b, &mut p);
        let alphabet: Vec<char> = std::str::from_utf8(&b[p..p + al])
            .unwrap()
            .chars()
            .collect();
        p += al;
        let c1w = rd_tensor(b, &mut p);
        let c1b = rd_tensor(b, &mut p);
        let c2w = rd_tensor(b, &mut p);
        let c2b = rd_tensor(b, &mut p);
        let fcw = rd_tensor(b, &mut p);
        let fcb = rd_tensor(b, &mut p);
        Model {
            alphabet,
            c1w,
            c1b,
            c2w,
            c2b,
            fcw,
            fcb,
        }
    }

    /// 识别一张验证码，返回 (识别串, 各字最小置信度)。分割不出恰好 4 个字形则 None。
    pub fn solve(&self, bytes: &[u8]) -> Option<(String, f32)> {
        let glyphs = segment(bytes)?;
        if glyphs.len() != 4 {
            return None;
        }
        let mut s = String::new();
        let mut minc = 1.0f32;
        for g in &glyphs {
            // TTA: 多角度平均 softmax
            let mut prob = vec![0f32; self.alphabet.len()];
            for deg in [-8.0f32, -4.0, 0.0, 4.0, 8.0] {
                let gg = rotate(g, deg);
                let pr = self.forward(&gg);
                for i in 0..prob.len() {
                    prob[i] += pr[i];
                }
            }
            let (mut bi, mut bv) = (0usize, -1f32);
            for (i, &p) in prob.iter().enumerate() {
                if p > bv {
                    bv = p;
                    bi = i;
                }
            }
            let conf = prob[bi] / 5.0;
            s.push(self.alphabet[bi]);
            if conf < minc {
                minc = conf;
            }
        }
        Some((s, minc))
    }

    fn forward(&self, glyph: &[f32]) -> Vec<f32> {
        // glyph: GH*GW = 28*20
        let p1 = maxpool2(
            &relu(&conv(glyph, 1, GH, GW, &self.c1w, &self.c1b)),
            8,
            GH,
            GW,
        );
        // p1: 8 x 14 x 10
        let p2 = maxpool2(
            &relu(&conv(&p1, 8, GH / 2, GW / 2, &self.c2w, &self.c2b)),
            16,
            GH / 2,
            GW / 2,
        );
        // p2: 16 x 7 x 5  -> flatten 560
        let feat = &p2; // already flat
        let out = self.fcw.shape[1];
        let inp = self.fcw.shape[0];
        let mut logits = vec![0f32; out];
        for (o, logit) in logits.iter_mut().enumerate() {
            let mut acc = self.fcb.data[o];
            for (i, &f) in feat.iter().enumerate().take(inp) {
                acc += f * self.fcw.data[i * out + o];
            }
            *logit = acc;
        }
        softmax(&logits)
    }
}

/// 分割：前景掩码 -> 8连通域(面积>=25) -> 按 x 排序 -> 每个 bbox 覆盖率归一到 28x20
fn segment(bytes: &[u8]) -> Option<Vec<Vec<f32>>> {
    let img = image::load_from_memory(bytes).ok()?.to_rgb8();
    let (w, h) = (img.width() as usize, img.height() as usize);
    if w == 0 || h == 0 || w > 2048 || h > 512 {
        return None;
    }
    let mut fg = vec![false; w * h];
    for y in 0..h {
        for x in 0..w {
            let p = img.get_pixel(x as u32, y as u32).0;
            let (r, gg, b) = (p[0] as i32, p[1] as i32, p[2] as i32);
            let mx = r.max(gg).max(b);
            let mn = r.min(gg).min(b);
            fg[y * w + x] = (mx - mn) > 60 || mx < 110;
        }
    }
    // 8连通域
    let mut lab = vec![0i32; w * h];
    let mut comps: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut stack: Vec<(usize, usize)> = Vec::new();
    for sy in 0..h {
        for sx in 0..w {
            if fg[sy * w + sx] && lab[sy * w + sx] == 0 {
                let id = comps.len() as i32 + 1;
                stack.clear();
                stack.push((sx, sy));
                lab[sy * w + sx] = id;
                let mut pts = Vec::new();
                while let Some((cx, cy)) = stack.pop() {
                    pts.push((cx, cy));
                    for dy in -1i32..=1 {
                        for dx in -1i32..=1 {
                            let nx = cx as i32 + dx;
                            let ny = cy as i32 + dy;
                            if nx < 0 || ny < 0 || nx >= w as i32 || ny >= h as i32 {
                                continue;
                            }
                            let (nx, ny) = (nx as usize, ny as usize);
                            if fg[ny * w + nx] && lab[ny * w + nx] == 0 {
                                lab[ny * w + nx] = id;
                                stack.push((nx, ny));
                            }
                        }
                    }
                }
                comps.push(pts);
            }
        }
    }
    let mut big: Vec<&Vec<(usize, usize)>> = comps.iter().filter(|c| c.len() >= 25).collect();
    big.sort_by_key(|c| c.iter().map(|p| p.0).min().unwrap());
    let mut out = Vec::new();
    for c in big {
        let x0 = c.iter().map(|p| p.0).min().unwrap();
        let x1 = c.iter().map(|p| p.0).max().unwrap();
        let y0 = c.iter().map(|p| p.1).min().unwrap();
        let y1 = c.iter().map(|p| p.1).max().unwrap();
        let gw = x1 - x0 + 1;
        let gh = y1 - y0 + 1;
        // 二值 crop
        let mut crop = vec![0f32; gw * gh];
        for &(px, py) in c {
            crop[(py - y0) * gw + (px - x0)] = 1.0;
        }
        // 双线性覆盖率缩放到 GWxGH（复刻 PIL BILINEAR）
        out.push(resize_bilinear(&crop, gw, gh, GW, GH));
    }
    Some(out)
}
