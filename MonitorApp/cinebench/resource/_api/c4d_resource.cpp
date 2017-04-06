
#include "c4d_resource.h"
#include "c4d_gui.h"

#ifndef __API_INTERN__
#include "c4d_memory.h"
#include "c4d_file.h"
#include "lib_description.h"

Bool RegisterDescription(Int32 id, const String& idstr, LocalResource* res)
{
	return Description_Register(id, idstr, res ? res : resource.Get());
}
#else

#include "ge_file.h"
#include "ge_memory.h"
#include "lib_description.h"

Bool RegisterDescription(Int32 id, const String& idstr, LocalResource* res)
{
	return Description_Register(id, idstr, nullptr);
}

#include "operatingsystem.h"
#endif

GeResource::GeResource(void)
{
	lr = nullptr;
	state	 = false;
	initfn = nullptr;
	glob = false;
}

GeResource::~GeResource(void)
{
	Free();
}

void GeResource::Free(void)
{
	if (glob)
		return;

	if (lr)
	{
		C4DOS.Lr->Free(lr, _regardIsStopped);
		lr = nullptr;
	}

	if (initfn)
		DeleteObj(initfn);
}

Bool GeResource::Init(void)
{
#ifndef __API_INTERN__
	return Init(GeGetPluginPath());
#else
	return Init(GeGetStartupPath());
#endif
}

Bool GeResource::Init(const Filename& path, Bool regardIsStopped)
{
	_regardIsStopped = regardIsStopped;
	if (!initfn)
	{
		initfn = NewObjClear(Filename, path);
		if (!initfn)
			return false;
	}

	if (state)
		return lr != nullptr;

	lr = C4DOS.Lr->Alloc((Filename*)&path);
	state = true;
	return lr != nullptr;
}

Bool GeResource::InitAsGlobal(void)
{
	glob = true;
	lr = C4DOS.Lr->GetCinemaResource();
	return lr != nullptr;
}

Bool GeResource::ReloadResource(void)
{
	if (glob)
		return true;
	if (!initfn)
		return false;
	return C4DOS.Lr->ReloadResource(lr, initfn);
}

const String& GeResource::LoadString(Int32 id)
{
#ifndef __API_INTERN__
	if (!lr)
		return *C4DOS.St->Default;
	return C4DOS.Lr->LoadString(lr, id);
#else
	return GeLoadString(id);
#endif
}

#ifndef __API_INTERN__
GeResource resource;

void FreeResource()
{
	resource.Free();
}

const String& GeLoadString(Int32 id)
{
	return resource.LoadString(id);
}

String GeLoadString(Int32 id, const String& p1)
{
	Int32	 pos;
	String str = resource.LoadString(id);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p1);
	return str;
}

String GeLoadString(Int32 id, const String& p1, const String& p2)
{
	Int32	 pos;
	String str = resource.LoadString(id);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p1);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p2);
	return str;
}

String GeLoadString(Int32 id, const String& p1, const String& p2, const String& p3)
{
	Int32	 pos;
	String str = resource.LoadString(id);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p1);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p2);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p3);
	return str;
}

String GeLoadString(Int32 id, const String& p1, const String& p2, const String& p3, const String& p4)
{
	Int32	 pos;
	String str = resource.LoadString(id);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p1);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p2);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p3);
	if (!str.FindFirst("#", &pos))
		return String();
	str.Delete(pos, 1);
	str.Insert(pos, p4);
	return str;
}

BaseContainer* GetMenuResource(const String& menuname)
{
	return C4DOS.Lr->GetMenuResource(menuname);
}

GeData* SearchPluginMenuResource(const String& identifier)
{
	BaseContainer* bc = GetMenuResource(String("M_EDITOR"));
	if (!bc)
		return nullptr;

	Int32						id;
	GeData*					last = nullptr, *dat;
	BrowseContainer browse(bc);
	while (browse.GetNext(&id, &dat))
	{
		if (id == MENURESOURCE_SUBMENU)
		{
			BaseContainer* dc = dat->GetContainer();
			if (dc && dc->GetString(MENURESOURCE_SUBTITLE) == identifier)
			{
				last = dat;
				break;
			}
		}
	}
	return last;
}

//Search through child menus
GeData* SearchPluginSubMenuResource(const String& identifier, BaseContainer* bc)
{
	if (!bc)
	{
		bc = GetMenuResource(String("M_EDITOR"));
		if (!bc)
			return nullptr;
	}

	Int32						id;
	GeData*					last = nullptr, *dat;
	BrowseContainer browse(bc);
	while (browse.GetNext(&id, &dat))
	{
		if (id == MENURESOURCE_SUBMENU)
		{
			BaseContainer* dc = dat->GetContainer();
			if (dc && dc->GetString(MENURESOURCE_SUBTITLE) == identifier)
			{
				last = dat;
				break;
			}
		}
		else if (id == MENURESOURCE_COMMAND)
		{
			if (dat && dat->GetString() == identifier)
			{
				last = dat;
				break;
			}
		}
	}
	return last;
}


Bool SearchMenuResource(BaseContainer* bc, const String& searchstr)
{
	if (!bc)
		return false;

	BrowseContainer browse(bc);

	Int32		id	= 0;
	GeData* dat = nullptr;

	while (browse.GetNext(&id, &dat))
	{
		if (id == MENURESOURCE_SUBMENU || id == MENURESOURCE_STRING)
		{
			if (SearchMenuResource(dat->GetContainer(), searchstr))
				return true;
		}
		else if (id == MENURESOURCE_COMMAND)
		{
			if (dat->GetString() == searchstr)
				return true;
		}
	}
	return false;
}

void UpdateMenus(void)
{
	C4DOS.Lr->UpdateMenus();
}

#endif
