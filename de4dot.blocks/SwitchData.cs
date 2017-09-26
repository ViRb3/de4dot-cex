namespace de4dot.blocks
{
    public class SwitchData
    {
        protected readonly Block _block;

        public int? Key;
        public bool IsKeyHardCoded;

        public SwitchData(Block block)
        {
            _block = block;
        }

        public virtual bool Initialize()
        {
            return false;
        }
    }
}
