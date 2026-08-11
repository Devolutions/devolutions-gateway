mod test_spec;

pub mod spec_write_read {
    use std::io::Cursor;

    use ebml_iterable::error::TagIteratorError;
    use ebml_iterable::specs::{EbmlTag, Master};
    use ebml_iterable::{TagIterator, TagWriter, WriteOptions};

    use super::test_spec::TestSpec;

    #[test]
    pub fn simple_read_write() {
        let tags: Vec<TestSpec> = vec![
            TestSpec::Ebml(Master::Start),
            TestSpec::Ebml(Master::End),
            TestSpec::Segment(Master::Start),
            TestSpec::TrackType(0x01),
            TestSpec::Segment(Master::End),
        ];

        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        for tag in tags.iter() {
            writer.write(tag).expect("Test shouldn't error");
        }

        println!("dest {:?}", dest);

        let mut src = Cursor::new(dest.get_ref().to_vec());
        let reader = TagIterator::new(&mut src, &[]);
        let read_tags: Vec<TestSpec> = reader.into_iter().map(|t| t.unwrap()).collect();

        println!("tags {:?}", read_tags);

        for i in 0..read_tags.len() {
            assert_eq!(tags[i], read_tags[i]);
        }
    }

    #[test]
    pub fn read_write_buffered_tag() {
        let tags: Vec<TestSpec> = vec![
            TestSpec::Segment(Master::Start),
            TestSpec::Cluster(Master::Full(vec![TestSpec::CueRefCluster(0x02)])),
            TestSpec::Segment(Master::End),
        ];

        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        for tag in tags.iter() {
            writer.write(tag).expect("Test shouldn't error");
        }

        println!("dest {:?}", dest);

        let mut src = Cursor::new(dest.get_ref().to_vec());
        let reader = TagIterator::new(&mut src, &[TestSpec::Cluster(Master::Start)]);
        let read_tags: Vec<TestSpec> = reader.into_iter().map(|t| t.unwrap()).collect();

        println!("tags {:?}", read_tags);

        for i in 0..read_tags.len() {
            assert_eq!(tags[i], read_tags[i]);
        }
    }

    #[test]
    pub fn oversized_tag() {
        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        writer
            .write(&TestSpec::Segment(Master::Start))
            .expect("Error writing tag");
        writer
            .write(&TestSpec::Cluster(Master::Start))
            .expect("Error writing tag");
        // Why 0x10001 specifically? This exceeds the default buffer length (0x10000)?!
        writer.write_raw(0xa1, &[0x00; 0x10001]).expect("Error writing tag");
        writer.write(&TestSpec::Count(0x00)).expect("Error writing tag");
        writer
            .write(&TestSpec::Cluster(Master::End))
            .expect("Error writing tag");
        writer
            .write(&TestSpec::Segment(Master::End))
            .expect("Error writing tag");
        drop(writer);

        dest.set_position(0);
        let iter = TagIterator::<_, TestSpec>::new(dest, &[]);

        let tags: Vec<_> = iter.into_iter().collect();
        assert_eq!(tags.len(), 4 + 2, "Reading every tag that was written");
    }

    #[test]
    pub fn write_unknown_size() {
        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        writer.write(&TestSpec::Root(Master::Start)).unwrap();
        writer
            .write_advanced(
                &TestSpec::Parent(Master::Start),
                WriteOptions::is_unknown_sized_element(),
            )
            .unwrap();
        writer.write(&TestSpec::Child(1)).unwrap();
        writer.write(&TestSpec::Child(2)).unwrap();
        writer.write(&TestSpec::Parent(Master::End)).unwrap();
        writer.write(&TestSpec::Root(Master::End)).unwrap();

        dest.set_position(0);

        let iter = TagIterator::<_, TestSpec>::new(dest, &[]);
        let tags: Vec<_> = iter.into_iter().collect();
        assert_eq!(tags.len(), 6, "Reading every tag that was written");
    }

    #[test]
    pub fn buffer_unknown_size() {
        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        writer.write(&TestSpec::Root(Master::Start)).unwrap();
        writer
            .write_advanced(
                &TestSpec::Parent(Master::Start),
                WriteOptions::is_unknown_sized_element(),
            )
            .unwrap();
        writer.write(&TestSpec::Child(1)).unwrap();
        writer.write(&TestSpec::Child(2)).unwrap();
        writer.write(&TestSpec::Parent(Master::End)).unwrap();
        writer.write(&TestSpec::Root(Master::End)).unwrap();

        dest.set_position(0);

        let iter = TagIterator::<_, TestSpec>::new(dest, &[TestSpec::Parent(Master::Start)]);
        let mut tags: Vec<_> = iter.into_iter().collect();
        assert_eq!(tags.len(), 3, "Buffering 'Parent' into full variant");

        tags.pop();
        let parent = tags.pop().unwrap().unwrap();
        assert!(
            matches!(parent.as_master(), Some(Master::Full(c)) if c.len() == 2),
            "Did not buffer tag as master with 2 children"
        );
    }

    #[test]
    pub fn unknown_size_write_read() {
        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        writer.write(&TestSpec::Root(Master::Start)).unwrap();
        writer
            .write_advanced(
                &TestSpec::Parent(Master::Start),
                WriteOptions::is_unknown_sized_element(),
            )
            .unwrap();
        writer.write(&TestSpec::Child(1)).unwrap();
        writer.write(&TestSpec::Child(2)).unwrap();
        writer.write(&TestSpec::Parent(Master::End)).unwrap();
        writer.write(&TestSpec::Int(2)).unwrap();
        writer.write(&TestSpec::Root(Master::End)).unwrap();

        println!("{dest:x?}");
        dest.set_position(0);

        let mut iter = TagIterator::<_, TestSpec>::new(dest, &[]);
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Root(Master::Start)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Parent(Master::Start)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Child(1)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Child(2)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Parent(Master::End)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Int(2)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Root(Master::End)))));
        assert!(matches!(iter.next(), None));
    }

    #[test]
    pub fn specific_size_length_write_read() {
        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        writer.write(&TestSpec::Root(Master::Start)).unwrap();
        writer
            .write_advanced(&TestSpec::Parent(Master::Start), WriteOptions::set_size_byte_count(8))
            .unwrap();
        writer.write(&TestSpec::Child(1)).unwrap();
        writer.write(&TestSpec::Child(2)).unwrap();
        writer.write(&TestSpec::Parent(Master::End)).unwrap();
        writer.write(&TestSpec::Int(2)).unwrap();
        writer.write(&TestSpec::Root(Master::End)).unwrap();

        println!("{dest:x?}");
        dest.set_position(0);

        let mut iter = TagIterator::<_, TestSpec>::new(dest, &[]);
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Root(Master::Start)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Parent(Master::Start)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Child(1)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Child(2)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Parent(Master::End)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Int(2)))));
        assert!(matches!(iter.next(), Some(Ok(TestSpec::Root(Master::End)))));
        assert!(matches!(iter.next(), None));
    }

    #[test]
    pub fn eof_error_is_helpful() {
        let tags: Vec<TestSpec> = vec![
            TestSpec::Segment(Master::Start),
            TestSpec::TrackType(0x01),
            TestSpec::Cluster(Master::Start),
            TestSpec::CueRefCluster(3),
            TestSpec::Count(1),
            TestSpec::Block(vec![0, 1, 2, 3, 4, 5, 6, 7, 8]),
            TestSpec::Cluster(Master::End),
            TestSpec::Segment(Master::End),
        ];

        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        for tag in tags.iter() {
            writer.write(tag).expect("Test shouldn't error");
        }

        println!("dest {:x?}", dest);

        let mut src = Cursor::new(dest.get_ref()[0..26].to_vec());
        let reader = TagIterator::new(&mut src, &[]);
        let mut iter = reader
            .into_iter()
            .skip_while(|x: &Result<TestSpec, TagIteratorError>| x.is_ok());

        let err = iter.next().expect("Shouldn't have reached end of data");

        match err.expect_err("Should be an error") {
            TagIteratorError::UnexpectedEOF {
                tag_start,
                tag_id,
                tag_size,
                partial_data: _,
            } => {
                assert_eq!(tag_start, 20);
                assert_eq!(tag_id, Some(TestSpec::Block(vec![]).get_id()));
                assert_eq!(tag_size, Some(9));
            }
            other => {
                println!("{other:?}");
                assert!(false);
            }
        }
    }

    #[test]
    pub fn eof_on_tag_size() {
        let tags: Vec<TestSpec> = vec![
            TestSpec::Segment(Master::Start),
            TestSpec::TrackType(0x01),
            TestSpec::Cluster(Master::Start),
            TestSpec::CueRefCluster(3),
            TestSpec::Count(1),
            TestSpec::Block(vec![0, 1, 2, 3, 4, 5, 6, 7]),
            TestSpec::Block(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
            TestSpec::Cluster(Master::End),
            TestSpec::Segment(Master::End),
        ];

        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        for tag in tags.iter() {
            writer.write(tag).expect("Test shouldn't error");
        }

        println!("dest {:x?}", dest);

        let mut src = Cursor::new(dest.get_ref()[0..31].to_vec());
        let reader = TagIterator::with_capacity(&mut src, &[], 10);
        let mut iter = reader
            .into_iter()
            .skip_while(|x: &Result<TestSpec, TagIteratorError>| x.is_ok());

        let err = iter.next().expect("Shouldn't have reached end of data");

        match err.expect_err("Should be an error") {
            TagIteratorError::UnexpectedEOF {
                tag_start,
                tag_id,
                tag_size,
                partial_data: _,
            } => {
                println!("got error - {tag_start}, {tag_id:?}, {tag_size:?}");
                assert_eq!(tag_start, 30);
                assert_eq!(tag_id, Some(TestSpec::Block(vec![]).get_id()));
                assert_eq!(tag_size, None);
            }
            other => {
                println!("{other:?}");
                assert!(false);
            }
        }
    }

    #[test]
    pub fn allow_start_reading_not_at_root() {
        let tags: Vec<TestSpec> = vec![
            TestSpec::Segment(Master::Start),
            TestSpec::TrackType(0x01),
            TestSpec::Cluster(Master::Start),
            TestSpec::CueRefCluster(3),
            TestSpec::Count(1),
            TestSpec::Block(vec![0, 1, 2, 3, 4, 5, 6, 7, 8]),
            TestSpec::Cluster(Master::End),
            TestSpec::Segment(Master::End),
        ];

        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        for tag in tags.iter() {
            writer.write(tag).expect("Test shouldn't error");
        }

        println!("dest {:x?}", dest);

        let mut src = Cursor::new(dest.get_ref()[8..].to_vec());
        let reader: TagIterator<_, TestSpec> = TagIterator::new(&mut src, &[]);
        reader.for_each(|t| assert!(t.is_ok()));
    }

    #[test]
    pub fn validate_global_hierarchies() {
        let tags: Vec<TestSpec> = vec![
            TestSpec::Ebml(Master::Start),
            TestSpec::Ebml(Master::End),
            TestSpec::Void(vec![0xa0]),
            TestSpec::Segment(Master::Start),
            TestSpec::Crc32(vec![0x01]),
            TestSpec::TrackType(0x01),
            TestSpec::Cluster(Master::Start),
            TestSpec::Crc32(vec![0x02]),
            TestSpec::Count(1),
            TestSpec::Cluster(Master::End),
            TestSpec::Segment(Master::End),
        ];

        let mut dest = Cursor::new(Vec::new());
        let mut writer = TagWriter::new(&mut dest);

        for tag in tags.iter() {
            writer.write(tag).expect("Test shouldn't error");
        }

        println!("dest {:?}", dest);

        let mut src = Cursor::new(dest.get_ref().to_vec());
        let reader = TagIterator::new(&mut src, &[]);
        let read_tags: Vec<TestSpec> = reader.into_iter().map(|t| t.unwrap()).collect();

        println!("tags {:?}", read_tags);

        for i in 0..read_tags.len() {
            assert_eq!(tags[i], read_tags[i]);
        }
    }
}
