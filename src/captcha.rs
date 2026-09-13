use anyhow::{Context, Result, ensure};
use image::{ImageReader, imageops::FilterType};
use std::io::{Cursor, IsTerminal, Write};
use std::path::Path;

pub fn display(bytes: &[u8], path: Option<&Path>, columns: u32) -> Result<()> {
    if let Some(path) = path {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .context("CAPTCHA file must not already exist")?;
        file.write_all(bytes)?;
        eprintln!("CAPTCHA saved: {}", path.display());
    }
    if std::io::stderr().is_terminal() {
        let mut output = std::io::stderr().lock();
        render(bytes, columns, &mut output)?;
        output.flush()?;
    } else {
        ensure!(
            path.is_some(),
            "Redirected terminal requires --captcha-file <image>"
        );
    }
    Ok(())
}

fn render(bytes: &[u8], columns: u32, output: &mut impl Write) -> Result<()> {
    let reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    let (width, height) = reader.into_dimensions()?;
    ensure!(
        width > 0 && height > 0 && width <= 2048 && height <= 512,
        "CAPTCHA dimensions are unsupported"
    );
    let columns = columns.clamp(2, 160);
    let rows = (height * columns / width).clamp(2, 64);
    let image = image::load_from_memory(bytes)?
        .resize_exact(columns, rows, FilterType::Nearest)
        .to_rgba8();
    let rgb = |x, y| {
        let pixel = image.get_pixel(x, y);
        let alpha = u32::from(pixel[3]);
        [0, 1, 2].map(|c| (u32::from(pixel[c]) * alpha + 255 * (255 - alpha)) / 255)
    };
    for y in (0..rows).step_by(2) {
        for x in 0..columns {
            let [r, g, b] = rgb(x, y);
            let [br, bg, bb] = if y + 1 < rows {
                rgb(x, y + 1)
            } else {
                [255; 3]
            };
            write!(output, "\x1b[38;2;{r};{g};{b}m\x1b[48;2;{br};{bg};{bb}m▀")?;
        }
        writeln!(output, "\x1b[0m")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_renders_color_and_resets_attributes() {
        let mut image = image::RgbaImage::new(2, 2);
        image.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
        image.put_pixel(0, 1, image::Rgba([0, 0, 255, 255]));
        let mut png = Cursor::new(Vec::new());
        image.write_to(&mut png, image::ImageFormat::Png).unwrap();
        let mut result = Vec::new();
        render(png.get_ref(), 2, &mut result).unwrap();
        let result = String::from_utf8(result).unwrap();
        assert!(result.contains("\x1b[38;2;255;0;0m\x1b[48;2;0;0;255m▀"));
        assert!(result.contains("38;2;255;255;255m"));
        assert!(result.ends_with("\x1b[0m\n"));
    }
}
