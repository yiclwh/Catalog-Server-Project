from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category

engine = create_engine('postgresql://catalog:catpassword@localhost/catalog') 
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

presets = ["antiques", "appliances", "arts+crafts", "atv/utv/sno", "auto parts", "baby+kid", 
"bikes", "boats", "books", "cars+trucks", "cell phones", "clothes", "computers", "electronics",
"free", "furniture", "garage sale", "general", "household", "materials", "motorcycles", "music instr",
"rvs+camp", "sporting", "tickets", "tools", "toys+games", "video gaming"]

categories = session.query(Category).all()

if not categories:
    for name in presets:
        category = Category(name = name)
        session.add(category)
        session.commit()
    print("Inserted preset categories.")