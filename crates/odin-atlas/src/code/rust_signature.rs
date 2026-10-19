//! Rust signature, structure, and visibility rendering for discovered symbols.

use syn::{
    AngleBracketedGenericArguments, BareFnArg, Expr, Fields, FnArg, GenericArgument, GenericParam,
    Generics, ItemEnum, ItemStruct, Lit, Pat, PathArguments, ReturnType, Signature, Type,
    TypeParamBound, Visibility,
};

pub(super) fn render_trait_type(value: &syn::TraitItemType) -> String {
    let bounds = if value.bounds.is_empty() {
        String::new()
    } else {
        format!(": {}", render_bounds(value.bounds.iter()))
    };
    let default = value
        .default
        .as_ref()
        .map_or(String::new(), |(_, ty)| format!(" = {}", render_type(ty)));
    format!(
        "type {}{}{bounds}{default}",
        value.ident,
        render_generics(&value.generics)
    )
}

pub(super) fn render_enum(item: &ItemEnum) -> String {
    let variants = item
        .variants
        .iter()
        .map(|variant| {
            let fields = render_fields(&variant.fields, true);
            if fields.is_empty() {
                variant.ident.to_string()
            } else {
                format!("{}{fields}", variant.ident)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "pub enum {}{} {{ {variants} }}{}",
        item.ident,
        render_generics_without_where(&item.generics),
        render_where(&item.generics)
    )
}

pub(super) fn render_struct(item: &ItemStruct) -> String {
    format!(
        "pub struct {}{}{}{}",
        item.ident,
        render_generics_without_where(&item.generics),
        render_fields(&item.fields, false),
        render_where(&item.generics)
    )
}

fn render_fields(fields: &Fields, inherited_public: bool) -> String {
    match fields {
        Fields::Named(fields) => {
            let values = fields
                .named
                .iter()
                .filter(|field| inherited_public || is_public(&field.vis))
                .map(|field| {
                    let visibility = if inherited_public { "" } else { "pub " };
                    format!(
                        "{visibility}{}: {}",
                        field
                            .ident
                            .as_ref()
                            .map_or("_".to_owned(), ToString::to_string),
                        render_type(&field.ty)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!(" {{ {values} }}")
        }
        Fields::Unnamed(fields) => {
            let values = fields
                .unnamed
                .iter()
                .map(|field| {
                    if inherited_public {
                        render_type(&field.ty)
                    } else if is_public(&field.vis) {
                        format!("pub {}", render_type(&field.ty))
                    } else {
                        "_".to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("({values})")
        }
        Fields::Unit => String::new(),
    }
}

pub(super) fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

pub(super) fn render_signature(signature: &Signature) -> String {
    let mut qualifiers = Vec::new();
    if signature.constness.is_some() {
        qualifiers.push("const".to_owned());
    }
    if signature.asyncness.is_some() {
        qualifiers.push("async".to_owned());
    }
    if signature.unsafety.is_some() {
        qualifiers.push("unsafe".to_owned());
    }
    if let Some(abi) = &signature.abi {
        qualifiers.push(abi.name.as_ref().map_or_else(
            || "extern".to_owned(),
            |name| {
                format!(
                    "extern {}",
                    serde_json::to_string(&name.value()).unwrap_or_else(|_| "\"C\"".to_owned())
                )
            },
        ));
    }
    let prefix = if qualifiers.is_empty() {
        String::new()
    } else {
        format!("{} ", qualifiers.join(" "))
    };
    let mut inputs = signature
        .inputs
        .iter()
        .map(render_fn_arg)
        .collect::<Vec<_>>();
    if signature.variadic.is_some() {
        inputs.push("...".to_owned());
    }
    let output = match &signature.output {
        ReturnType::Default => String::new(),
        ReturnType::Type(_, ty) => format!(" -> {}", render_type(ty)),
    };
    format!(
        "{prefix}fn {}{}({}){output}{}",
        signature.ident,
        render_generics_without_where(&signature.generics),
        inputs.join(", "),
        render_where(&signature.generics)
    )
}

fn render_fn_arg(argument: &FnArg) -> String {
    match argument {
        FnArg::Receiver(receiver) if receiver.colon_token.is_some() => {
            format!("self: {}", render_type(&receiver.ty))
        }
        FnArg::Receiver(receiver) => {
            let reference = receiver.reference.as_ref().map_or("", |_| "&");
            let lifetime = receiver
                .reference
                .as_ref()
                .and_then(|(_, lifetime)| lifetime.as_ref())
                .map_or(String::new(), |lifetime| {
                    format!("{} ", render_lifetime(lifetime))
                });
            let mutable = if receiver.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!("{reference}{lifetime}{mutable}self")
        }
        FnArg::Typed(argument) => {
            format!(
                "{}: {}",
                render_pat(&argument.pat),
                render_type(&argument.ty)
            )
        }
    }
}

fn render_pat(pattern: &Pat) -> String {
    match pattern {
        Pat::Ident(pattern) => {
            let reference = if pattern.by_ref.is_some() { "ref " } else { "" };
            let mutable = if pattern.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            let subpattern = pattern
                .subpat
                .as_ref()
                .map_or(String::new(), |(_, pattern)| {
                    format!(" @ {}", render_pat(pattern))
                });
            format!("{reference}{mutable}{}{subpattern}", pattern.ident)
        }
        Pat::Reference(pattern) => {
            let mutable = if pattern.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!("&{mutable}{}", render_pat(&pattern.pat))
        }
        Pat::Tuple(pattern) => {
            let values = pattern
                .elems
                .iter()
                .map(render_pat)
                .collect::<Vec<_>>()
                .join(", ");
            format!("({values})")
        }
        Pat::Wild(_) => "_".to_owned(),
        _ => "_".to_owned(),
    }
}

pub(super) fn render_generics(generics: &Generics) -> String {
    format!(
        "{}{}",
        render_generics_without_where(generics),
        render_where(generics)
    )
}

pub(super) fn render_generics_without_where(generics: &Generics) -> String {
    if generics.params.is_empty() {
        return String::new();
    }
    let params = generics
        .params
        .iter()
        .map(|parameter| match parameter {
            GenericParam::Lifetime(parameter) => {
                let bounds = parameter
                    .bounds
                    .iter()
                    .map(render_lifetime)
                    .collect::<Vec<_>>()
                    .join(" + ");
                if bounds.is_empty() {
                    render_lifetime(&parameter.lifetime)
                } else {
                    format!("{}: {bounds}", render_lifetime(&parameter.lifetime))
                }
            }
            GenericParam::Type(parameter) => {
                let bounds = render_bounds(parameter.bounds.iter());
                let default = parameter
                    .default
                    .as_ref()
                    .map_or(String::new(), |ty| format!(" = {}", render_type(ty)));
                if bounds.is_empty() {
                    format!("{}{default}", parameter.ident)
                } else {
                    format!("{}: {bounds}{default}", parameter.ident)
                }
            }
            GenericParam::Const(parameter) => {
                let default = parameter
                    .default
                    .as_ref()
                    .map_or(String::new(), |expression| {
                        format!(" = {}", render_expr(expression))
                    });
                format!(
                    "const {}: {}{default}",
                    parameter.ident,
                    render_type(&parameter.ty)
                )
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("<{params}>")
}

pub(super) fn render_where(generics: &Generics) -> String {
    let Some(clause) = &generics.where_clause else {
        return String::new();
    };
    let predicates = clause
        .predicates
        .iter()
        .map(|predicate| match predicate {
            syn::WherePredicate::Lifetime(predicate) => format!(
                "{}: {}",
                render_lifetime(&predicate.lifetime),
                predicate
                    .bounds
                    .iter()
                    .map(render_lifetime)
                    .collect::<Vec<_>>()
                    .join(" + ")
            ),
            syn::WherePredicate::Type(predicate) => format!(
                "{}: {}",
                render_type(&predicate.bounded_ty),
                render_bounds(predicate.bounds.iter())
            ),
            _ => "_".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(" where {predicates}")
}

pub(super) fn render_bounds<'a>(bounds: impl Iterator<Item = &'a TypeParamBound>) -> String {
    bounds
        .map(|bound| match bound {
            TypeParamBound::Lifetime(lifetime) => render_lifetime(lifetime),
            TypeParamBound::Trait(bound) => {
                let modifier = match &bound.modifier {
                    syn::TraitBoundModifier::None => "",
                    syn::TraitBoundModifier::Maybe(_) => "?",
                };
                format!("{modifier}{}", render_path(&bound.path))
            }
            _ => "_".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

pub(super) fn render_type(ty: &Type) -> String {
    match ty {
        Type::Array(ty) => format!("[{}; {}]", render_type(&ty.elem), render_expr(&ty.len)),
        Type::BareFn(ty) => {
            let lifetimes = ty
                .lifetimes
                .as_ref()
                .map_or(String::new(), render_bound_lifetimes);
            let unsafe_prefix = if ty.unsafety.is_some() { "unsafe " } else { "" };
            let abi = ty.abi.as_ref().map_or(String::new(), |abi| {
                abi.name.as_ref().map_or_else(
                    || "extern ".to_owned(),
                    |name| {
                        format!(
                            "extern {} ",
                            serde_json::to_string(&name.value())
                                .unwrap_or_else(|_| "\"C\"".to_owned())
                        )
                    },
                )
            });
            let mut inputs = ty.inputs.iter().map(render_bare_fn_arg).collect::<Vec<_>>();
            if ty.variadic.is_some() {
                inputs.push("...".to_owned());
            }
            let output = match &ty.output {
                ReturnType::Default => String::new(),
                ReturnType::Type(_, output) => format!(" -> {}", render_type(output)),
            };
            format!(
                "{lifetimes}{unsafe_prefix}{abi}fn({}){output}",
                inputs.join(", ")
            )
        }
        Type::Group(ty) => render_type(&ty.elem),
        Type::ImplTrait(ty) => format!("impl {}", render_bounds(ty.bounds.iter())),
        Type::Infer(_) => "_".to_owned(),
        Type::Macro(ty) => format!("{}!", render_path(&ty.mac.path)),
        Type::Never(_) => "!".to_owned(),
        Type::Paren(ty) => format!("({})", render_type(&ty.elem)),
        Type::Path(ty) => render_type_path(ty),
        Type::Ptr(ty) => {
            let mutability = if ty.mutability.is_some() {
                "mut"
            } else {
                "const"
            };
            format!("*{mutability} {}", render_type(&ty.elem))
        }
        Type::Reference(ty) => {
            let lifetime = ty.lifetime.as_ref().map_or(String::new(), |value| {
                format!("{} ", render_lifetime(value))
            });
            let mutable = if ty.mutability.is_some() { "mut " } else { "" };
            format!("&{lifetime}{mutable}{}", render_type(&ty.elem))
        }
        Type::Slice(ty) => format!("[{}]", render_type(&ty.elem)),
        Type::TraitObject(ty) => {
            let dyn_token = if ty.dyn_token.is_some() { "dyn " } else { "" };
            format!("{dyn_token}{}", render_bounds(ty.bounds.iter()))
        }
        Type::Tuple(ty) => {
            let values = ty
                .elems
                .iter()
                .map(render_type)
                .collect::<Vec<_>>()
                .join(", ");
            if ty.elems.len() == 1 {
                format!("({values},)")
            } else {
                format!("({values})")
            }
        }
        _ => "_".to_owned(),
    }
}

fn render_bound_lifetimes(lifetimes: &syn::BoundLifetimes) -> String {
    let values = lifetimes
        .lifetimes
        .iter()
        .filter_map(|parameter| match parameter {
            GenericParam::Lifetime(parameter) => Some(render_lifetime(&parameter.lifetime)),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("for<{values}> ")
}

fn render_type_path(ty: &syn::TypePath) -> String {
    let Some(qself) = &ty.qself else {
        return render_path(&ty.path);
    };
    let segments = ty.path.segments.iter().collect::<Vec<_>>();
    let before = render_path_segment_slice(&segments[..qself.position]);
    let after = render_path_segment_slice(&segments[qself.position..]);
    if before.is_empty() {
        format!("<{}>::{after}", render_type(&qself.ty))
    } else if after.is_empty() {
        format!("<{} as {before}>", render_type(&qself.ty))
    } else {
        format!("<{} as {before}>::{after}", render_type(&qself.ty))
    }
}

fn render_path_segment_slice(segments: &[&syn::PathSegment]) -> String {
    segments
        .iter()
        .map(|segment| {
            format!(
                "{}{}",
                segment.ident,
                render_path_arguments(&segment.arguments)
            )
        })
        .collect::<Vec<_>>()
        .join("::")
}

fn render_bare_fn_arg(argument: &BareFnArg) -> String {
    argument.name.as_ref().map_or_else(
        || render_type(&argument.ty),
        |(name, _)| format!("{name}: {}", render_type(&argument.ty)),
    )
}

fn render_path(path: &syn::Path) -> String {
    let leading = if path.leading_colon.is_some() {
        "::"
    } else {
        ""
    };
    let segments = path
        .segments
        .iter()
        .map(|segment| {
            format!(
                "{}{}",
                segment.ident,
                render_path_arguments(&segment.arguments)
            )
        })
        .collect::<Vec<_>>()
        .join("::");
    format!("{leading}{segments}")
}

fn render_path_arguments(arguments: &PathArguments) -> String {
    match arguments {
        PathArguments::None => String::new(),
        PathArguments::AngleBracketed(arguments) => render_angle_arguments(arguments),
        PathArguments::Parenthesized(arguments) => {
            let inputs = arguments
                .inputs
                .iter()
                .map(render_type)
                .collect::<Vec<_>>()
                .join(", ");
            let output = match &arguments.output {
                ReturnType::Default => String::new(),
                ReturnType::Type(_, output) => format!(" -> {}", render_type(output)),
            };
            format!("({inputs}){output}")
        }
    }
}

fn render_angle_arguments(arguments: &AngleBracketedGenericArguments) -> String {
    let values = arguments
        .args
        .iter()
        .map(|argument| match argument {
            GenericArgument::Lifetime(lifetime) => render_lifetime(lifetime),
            GenericArgument::Type(ty) => render_type(ty),
            GenericArgument::Const(expression) => render_expr(expression),
            GenericArgument::AssocType(binding) => {
                format!("{} = {}", binding.ident, render_type(&binding.ty))
            }
            GenericArgument::Constraint(binding) => {
                format!(
                    "{}: {}",
                    binding.ident,
                    render_bounds(binding.bounds.iter())
                )
            }
            _ => "_".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("<{values}>")
}

fn render_expr(expression: &Expr) -> String {
    match expression {
        Expr::Lit(expression) => render_lit(&expression.lit),
        Expr::Path(expression) => render_path(&expression.path),
        Expr::Unary(expression) => {
            let operator = match &expression.op {
                syn::UnOp::Deref(_) => "*",
                syn::UnOp::Not(_) => "!",
                syn::UnOp::Neg(_) => "-",
                _ => "_",
            };
            format!("{operator}{}", render_expr(&expression.expr))
        }
        Expr::Paren(expression) => format!("({})", render_expr(&expression.expr)),
        _ => "_".to_owned(),
    }
}

fn render_lit(literal: &Lit) -> String {
    match literal {
        Lit::Str(value) => {
            serde_json::to_string(&value.value()).unwrap_or_else(|_| "\"\"".to_owned())
        }
        Lit::ByteStr(value) => format!("b{:?}", value.value()),
        Lit::Byte(value) => format!("b'{}'", value.value()),
        Lit::Char(value) => format!("{:?}", value.value()),
        Lit::Int(value) => format!("{}{}", value.base10_digits(), value.suffix()),
        Lit::Float(value) => format!("{}{}", value.base10_digits(), value.suffix()),
        Lit::Bool(value) => value.value.to_string(),
        _ => "_".to_owned(),
    }
}

fn render_lifetime(lifetime: &syn::Lifetime) -> String {
    format!("'{}", lifetime.ident)
}
