use ebml_iterable_specification::{EbmlSpecification, EbmlTag, PathPart};

use crate::tag_iterator_util::EBMLSize;

///
/// Returns whether or not the a `test_id` is a parent of `current_id`.
///
pub fn is_parent<T: EbmlSpecification<T> + EbmlTag<T> + Clone>(current_id: u64, test_id: u64) -> bool {
    let path = <T>::get_path_by_id(current_id);
    path.iter().any(|p| matches!(p, PathPart::Id(p) if p == &test_id))
}

///
/// Returns whether or not the `test_id` is a sibling of `current_id`.
///
/// A sibling tag is one which shares the same direct parent.  A separate instance of the current tag counts as a sibling.
///
pub fn is_sibling<T: EbmlSpecification<T> + EbmlTag<T> + Clone>(current_id: u64, test_id: u64) -> bool {
    <T>::get_path_by_id(current_id) == <T>::get_path_by_id(test_id)
}

///
/// Returns whether or not the `test_id` would end this "Unknown" sized `current_id`.
///
/// Regarding this method, unknown sized tags can be ended if we reach an element that is:
///  - A parent of the tag
///  - A direct sibling of the tag
///  - A Root element
///
/// There are a couple of other cases where an Unknown sized tag can end, but they rely on knowing document position and tag sizes.  More details can be found in the [EBML RFC](https://www.rfc-editor.org/rfc/rfc8794.html#name-unknown-data-size).
///
pub fn is_ended_by<T: EbmlSpecification<T> + EbmlTag<T> + Clone>(current_id: u64, test_id: u64) -> bool {
    is_parent::<T>(current_id, test_id) || // parent
    is_sibling::<T>(current_id, test_id) || // sibling
    ( // Root element
        <T>::get_tag_data_type(test_id).is_some() &&
        <T>::get_path_by_id(test_id).is_empty()
    )
}

#[inline(always)]
pub fn validate_tag_path<T: EbmlSpecification<T> + EbmlTag<T> + Clone>(
    tag_id: u64,
    doc_path: impl Iterator<Item = (u64, EBMLSize, usize)>,
) -> bool {
    let path = <T>::get_path_by_id(tag_id);
    let mut path_marker = 0;
    let mut global_counter = 0;
    for item in doc_path {
        let current_node_id = item.0;

        if !item.1.is_known() && is_ended_by::<T>(current_node_id, tag_id) {
            return true;
        }

        if path_marker >= path.len() {
            return false;
        }

        match path[path_marker] {
            PathPart::Id(id) => {
                if id != current_node_id {
                    return false;
                }
                path_marker += 1;
            }
            PathPart::Global((min, max)) => {
                global_counter += 1;
                if max.is_some() && global_counter > max.unwrap_or_default() {
                    return false;
                }
                if path.len() > (path_marker + 1)
                    && matches!(path[path_marker + 1], PathPart::Id(id) if id == current_node_id)
                {
                    if min.is_some() && global_counter < min.unwrap_or_default() {
                        return false;
                    }
                    path_marker += 2;
                    global_counter = 0;
                }
            }
        }
    }

    // Validate that we compared ALL parents in the path
    path.len() == path_marker ||
    // or that the last parent was a global whose minimum was met
        ((path.len() - 1) == path_marker && matches!(path[path_marker], PathPart::Global((min, _)) if global_counter >= min.unwrap_or(0)))
}
