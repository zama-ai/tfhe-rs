pub trait Container: AsRef<[Self::Element]> {
    type Element;

    fn container_len(&self) -> usize {
        self.as_ref().len()
    }
}

pub trait ContainerMut: Container + AsMut<[<Self as Container>::Element]> {}

impl<T> Container for [T] {
    type Element = T;
}

impl<T> ContainerMut for [T] {}

impl<T> Container for Vec<T> {
    type Element = T;
}

impl<T> ContainerMut for Vec<T> {}

impl<T> Container for &[T] {
    type Element = T;
}

impl<T> Container for &mut [T] {
    type Element = T;
}

impl<T> ContainerMut for &mut [T] {}
