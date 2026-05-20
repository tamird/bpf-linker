use super::{ProfileDecl, expand_btf};

fn expand(input: &str, flavor: Option<&str>) -> String {
    let item = syn::parse_str(input).unwrap();
    let flavor = flavor.map(|flavor| syn::parse_str(flavor).unwrap());
    let tokens = expand_btf(item, flavor).unwrap();
    let file = syn::parse2(tokens).unwrap();
    prettyplease::unparse(&file)
}

fn expand_profile(input: &str) -> String {
    let declaration = syn::parse_str::<ProfileDecl>(input).unwrap();
    let tokens = super::expand_profile(declaration);
    let file = syn::parse2(tokens).unwrap();
    prettyplease::unparse(&file)
}

#[test]
fn expands_flavored_nested_schema() {
    insta::assert_binary_snapshot!(
        "flavored_nested_schema.rs",
        expand(
            r#"
            pub struct task_struct {
                pid: i32,
                se: sched_entity,
            }
            "#,
            Some("modern"),
        )
        .into_bytes(),
    );
}

#[test]
fn expands_profile_witness() {
    insta::assert_binary_snapshot!(
        "profile_witness.rs",
        expand_profile(
            r#"
            pub struct Profile {
                detect {
                    task_struct.__state,
                }
            }
            "#,
        )
        .into_bytes(),
    );
}
