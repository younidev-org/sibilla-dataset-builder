//! Generate safe PDFs for a reproducible demonstration; never reads external samples.
use anyhow::{Context, Result};
use lopdf::{Document, Object, Stream, dictionary};
/// Generate and verify three safe one-page PDFs in a new fixture directory.
fn main() -> Result<()> {
    let output = std::env::args_os()
        .nth(1)
        .context("usage: generate_fixtures OUTPUT_DIRECTORY (must not exist)")?;
    let output = std::path::Path::new(&output);
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir(output)?;
    for i in 0..3 {
        let mut doc = Document::with_version("1.7");
        let pages = doc.new_object_id();
        let content = doc.add_object(Stream::new(
            dictionary! {},
            format!("% safe fixture {i}\n").into_bytes(),
        ));
        let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages,"MediaBox"=>vec![Object::Integer(0),Object::Integer(0),Object::Integer(100),Object::Integer(100)],"Contents"=>content,"Resources"=>dictionary!{}});
        doc.objects.insert(
            pages,
            Object::Dictionary(dictionary! {"Type"=>"Pages","Count"=>1,"Kids"=>vec![page.into()]}),
        );
        let root = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages});
        doc.trailer.set("Root", root);
        let path = output.join(format!("safe-{i}.pdf"));
        doc.save(&path)?;
        assert_eq!(Document::load(&path)?.get_pages().len(), 1);
    }
    Ok(())
}
